import hashlib
import json
from unittest import TestCase

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, encode_cbor
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidBackupFlags
from webauthn.helpers.structs import (
    CredentialDeviceType,
    SignCountPolicy,
    SignCountTransition,
)


def _generate_credential():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()
    cose_public_key = encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
        }
    )
    return private_key, cose_public_key


def _build_credential_json(
    private_key,
    *,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5000",
    challenge: bytes = b"local-test-challenge",
    sign_count: int,
    up: bool = True,
    uv: bool = False,
    be: bool = False,
    bs: bool = False,
    sign: bool = True,
) -> str:
    flags = 0
    if up:
        flags |= 1 << 0
    if uv:
        flags |= 1 << 2
    if be:
        flags |= 1 << 3
    if bs:
        flags |= 1 << 4

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    auth_data = rp_id_hash + bytes([flags]) + sign_count.to_bytes(4, "big")

    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": bytes_to_base64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")

    client_data_hash = hashlib.sha256(client_data).digest()
    if sign:
        signature = private_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
    else:
        # A well-formed signature over the wrong data, so verification must fail
        signature = private_key.sign(b"wrong-data", ec.ECDSA(hashes.SHA256()))

    credential_id = b"local-test-credential-id"
    return json.dumps(
        {
            "id": bytes_to_base64url(credential_id),
            "rawId": bytes_to_base64url(credential_id),
            "response": {
                "authenticatorData": bytes_to_base64url(auth_data),
                "clientDataJSON": bytes_to_base64url(client_data),
                "signature": bytes_to_base64url(signature),
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
    )


class TestVerifyAuthenticationResponseSignCount(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.cose_public_key = _generate_credential()

    def _verify(self, *, stored_count: int, reported_count: int, **kwargs):
        build_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in ("be", "bs", "sign")}
        credential = _build_credential_json(
            self.private_key, sign_count=reported_count, **build_kwargs
        )
        return verify_authentication_response(
            credential=credential,
            expected_challenge=b"local-test-challenge",
            expected_rp_id="localhost",
            expected_origin="http://localhost:5000",
            credential_public_key=self.cose_public_key,
            credential_current_sign_count=stored_count,
            **kwargs,
        )

    def test_strict_policy_is_default_and_rejects_non_increasing_count(self):
        with self.assertRaisesRegex(
            InvalidAuthenticationResponse,
            "Response sign count of 5 was not greater than current count of 5",
        ):
            self._verify(stored_count=5, reported_count=5)

    def test_report_policy_zero_to_zero_is_not_a_risk(self):
        verification = self._verify(
            stored_count=0,
            reported_count=0,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.ZERO_TO_ZERO
        assert assessment.previous_sign_count == 0
        assert assessment.new_sign_count == 0
        assert not assessment.is_risk

    def test_report_policy_counting_started_is_not_a_risk(self):
        verification = self._verify(
            stored_count=0,
            reported_count=3,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.COUNTING_STARTED
        assert not assessment.is_risk

    def test_report_policy_normal_increment_is_not_a_risk(self):
        verification = self._verify(
            stored_count=3,
            reported_count=4,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NORMAL_INCREMENT
        assert not assessment.is_risk

    def test_report_policy_equal_positive_count_is_a_risk(self):
        verification = self._verify(
            stored_count=5,
            reported_count=5,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NOT_INCREMENTED
        assert assessment.is_risk
        assert assessment.previous_sign_count == 5
        assert assessment.new_sign_count == 5
        assert any("cloned credential" in reason for reason in assessment.reasons)

    def test_report_policy_regressed_count_is_a_risk(self):
        verification = self._verify(
            stored_count=5,
            reported_count=2,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NOT_INCREMENTED
        assert assessment.is_risk

    def test_report_policy_records_backup_state_in_assessment(self):
        verification = self._verify(
            stored_count=0,
            reported_count=0,
            be=True,
            bs=True,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.credential_device_type == CredentialDeviceType.MULTI_DEVICE
        assert assessment.credential_backed_up is True

    def test_report_policy_does_not_flag_synced_credential_with_normal_increment(self):
        verification = self._verify(
            stored_count=10,
            reported_count=11,
            be=True,
            bs=True,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NORMAL_INCREMENT
        assert not assessment.is_risk

    def test_report_policy_backup_eligibility_does_not_skip_counter_risk(self):
        verification = self._verify(
            stored_count=10,
            reported_count=10,
            be=True,
            bs=True,
            sign_count_policy=SignCountPolicy.REPORT,
        )
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NOT_INCREMENTED
        assert assessment.is_risk

    def test_report_policy_still_rejects_invalid_signature(self):
        with self.assertRaisesRegex(
            InvalidAuthenticationResponse,
            "Could not verify authentication signature",
        ):
            self._verify(
                stored_count=5,
                reported_count=5,
                sign=False,
                sign_count_policy=SignCountPolicy.REPORT,
            )

    def test_report_policy_still_rejects_invalid_backup_flags(self):
        # A single-device credential (BE=0) claiming to be backed up (BS=1)
        with self.assertRaises(InvalidBackupFlags):
            self._verify(
                stored_count=0,
                reported_count=0,
                be=False,
                bs=True,
                sign_count_policy=SignCountPolicy.REPORT,
            )

    def test_strict_policy_success_includes_assessment(self):
        verification = self._verify(stored_count=3, reported_count=4)
        assessment = verification.sign_count_assessment
        assert assessment.transition == SignCountTransition.NORMAL_INCREMENT
        assert not assessment.is_risk
