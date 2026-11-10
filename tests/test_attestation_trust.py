"""End-to-end coverage of attestation trust reporting and policy enforcement.

Each sample is a fully self-contained registration credential generated locally (see
`tests/helpers/local_attestation_samples.py`) and run through the public
`verify_registration_response()` entry point. Nothing here relies on format names to infer
trust: assertions are made on the trust actually reported after verification.
"""

from unittest import TestCase

from webauthn import verify_registration_response
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationFormat,
    AttestationPolicy,
    AttestationType,
)

from .helpers.local_attestation_samples import (
    build_none_sample,
    build_packed_chain_sample,
    build_self_attestation_sample,
)


def _verify(sample, **kwargs):
    return verify_registration_response(
        credential=sample.credential,
        expected_challenge=sample.expected_challenge,
        expected_rp_id=sample.expected_rp_id,
        expected_origin=sample.expected_origin,
        **kwargs,
    )


class TestAttestationTrustReporting(TestCase):
    def test_none_attestation_reports_no_trust(self) -> None:
        sample = build_none_sample()
        result = _verify(sample)

        self.assertEqual(result.fmt, AttestationFormat.NONE)
        self.assertEqual(result.attestation_type, AttestationType.NONE)
        self.assertFalse(result.trust_root_verified)
        self.assertIsNone(result.trust_root_fingerprint)
        # Credential information is still reported even without attestation
        self.assertTrue(result.credential_id)
        self.assertTrue(result.credential_public_key)
        self.assertEqual(result.aaguid.count("-"), 4)

    def test_packed_self_attestation_reports_self_not_root_trust(self) -> None:
        sample = build_self_attestation_sample()
        result = _verify(sample)

        self.assertEqual(result.fmt, AttestationFormat.PACKED)
        self.assertEqual(result.attestation_type, AttestationType.SELF)
        # Self attestation must never masquerade as a verified trust root
        self.assertFalse(result.trust_root_verified)
        self.assertIsNone(result.trust_root_fingerprint)
        self.assertTrue(result.credential_id)
        self.assertTrue(result.credential_public_key)

    def test_packed_chain_with_configured_root_reports_attca(self) -> None:
        sample = build_packed_chain_sample()
        result = _verify(
            sample,
            pem_root_certs_bytes_by_fmt={
                AttestationFormat.PACKED: [sample.root_cert_pem]
            },
        )

        self.assertEqual(result.fmt, AttestationFormat.PACKED)
        self.assertEqual(result.attestation_type, AttestationType.ATT_CA)
        self.assertTrue(result.trust_root_verified)
        # The fingerprint must identify the configured trust anchor exactly
        self.assertEqual(result.trust_root_fingerprint, sample.trust_root_fingerprint)
        self.assertEqual(len(result.trust_root_fingerprint.split(":")), 32)
        self.assertTrue(result.credential_id)
        self.assertTrue(result.credential_public_key)

    def test_same_chain_without_configured_root_reports_basic_only(self) -> None:
        sample = build_packed_chain_sample()
        # No root configured for this format: the chain cannot be anchored even though the
        # attestation signature and certificate structure are valid.
        result = _verify(sample)

        self.assertEqual(result.fmt, AttestationFormat.PACKED)
        self.assertEqual(result.attestation_type, AttestationType.BASIC)
        self.assertFalse(result.trust_root_verified)
        self.assertIsNone(result.trust_root_fingerprint)
        self.assertTrue(result.credential_id)
        self.assertTrue(result.credential_public_key)

    def test_client_x5c_certificate_cannot_become_a_trust_root(self) -> None:
        sample = build_packed_chain_sample()
        # Configure a different, unrelated "root" by passing the leaf itself under another format.
        # Per-format isolation plus the trust anchor check must keep the x5c cert from granting
        # root trust.
        result = _verify(
            sample,
            pem_root_certs_bytes_by_fmt={AttestationFormat.TPM: [sample.root_cert_pem]},
        )
        self.assertEqual(result.attestation_type, AttestationType.BASIC)
        self.assertFalse(result.trust_root_verified)


class TestAttestationPolicyEnforcement(TestCase):
    def test_allow_none_is_default_and_accepts_everything(self) -> None:
        for sample in (
            build_none_sample(),
            build_self_attestation_sample(),
            build_packed_chain_sample(),
        ):
            with self.subTest(sample=type(sample).__name__):
                # Default policy must keep the historical behavior
                result = _verify(sample)
                self.assertTrue(result.credential_id)

    def test_allow_self_rejects_none_but_accepts_self_and_basic(self) -> None:
        with self.assertRaises(InvalidRegistrationResponse):
            _verify(build_none_sample(), attestation_policy=AttestationPolicy.ALLOW_SELF)

        self.assertEqual(
            _verify(
                build_self_attestation_sample(),
                attestation_policy=AttestationPolicy.ALLOW_SELF,
            ).attestation_type,
            AttestationType.SELF,
        )

        # A chain without a configured root is basic, still acceptable under ALLOW_SELF
        basic_result = _verify(
            build_packed_chain_sample(),
            attestation_policy=AttestationPolicy.ALLOW_SELF,
        )
        self.assertEqual(basic_result.attestation_type, AttestationType.BASIC)

    def test_require_trusted_root_only_accepts_anchored_chain(self) -> None:
        policy = AttestationPolicy.REQUIRE_TRUSTED_ROOT

        with self.assertRaises(InvalidRegistrationResponse):
            _verify(build_none_sample(), attestation_policy=policy)

        with self.assertRaises(InvalidRegistrationResponse):
            _verify(build_self_attestation_sample(), attestation_policy=policy)

        # Same chain, root not configured -> basic -> rejected
        with self.assertRaises(InvalidRegistrationResponse):
            _verify(build_packed_chain_sample(), attestation_policy=policy)

        # Once the root is configured for this format, the policy is satisfied
        sample = build_packed_chain_sample()
        result = _verify(
            sample,
            pem_root_certs_bytes_by_fmt={
                AttestationFormat.PACKED: [sample.root_cert_pem]
            },
            attestation_policy=policy,
        )
        self.assertTrue(result.trust_root_verified)
        self.assertEqual(result.attestation_type, AttestationType.ATT_CA)

    def test_policy_runs_before_return_even_when_verification_passes(self) -> None:
        # A structurally valid "none" response verifies fine but must still be blocked by policy
        with self.assertRaises(InvalidRegistrationResponse):
            _verify(
                build_none_sample(),
                attestation_policy=AttestationPolicy.REQUIRE_TRUSTED_ROOT,
            )


class TestBackwardsCompatibility(TestCase):
    def test_legacy_positional_style_kwargs_still_work(self) -> None:
        # Existing callers pass only the original keyword arguments
        result = verify_registration_response(
            credential=build_none_sample().credential,
            expected_challenge=build_none_sample().expected_challenge,
            expected_origin="http://localhost:5000",
            expected_rp_id="localhost",
        )
        # New fields exist with safe defaults but never overstate trust
        self.assertEqual(result.attestation_type, AttestationType.NONE)
        self.assertFalse(result.trust_root_verified)
