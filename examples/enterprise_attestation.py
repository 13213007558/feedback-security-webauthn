"""Requiring an enterprise-trusted device at registration.

The attestation policy is enforced inside `verify_registration_response()`, so the caller never
has to infer device trust from a format name (`fmt`) or from catching exceptions. On success the
returned object explicitly states the attestation type, whether a trust root was verified, and
the fingerprint of the root that anchored the chain.
"""

from webauthn import verify_registration_response
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationFormat,
    AttestationPolicy,
    AttestationType,
)

# Roots stay isolated per attestation format. Only certificates configured here (or the roots
# built into a format) can act as trust anchors; certificates carried in the client's x5c can
# never add themselves as roots.
PEM_ROOT_CERTS_BY_FMT = {
    AttestationFormat.PACKED: [
        # PEM-encoded enterprise/attestation CA roots trusted for packed statements
        # open("enterprise_attestation_root.pem", "rb").read(),
    ],
    AttestationFormat.TPM: [
        # PEM-encoded roots trusted for TPM statements
    ],
}


def register_enterprise_device(credential: dict, expected_challenge: bytes) -> dict:
    """Register a credential only when the device proves a chain to a configured trust root."""
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id="login.example.com",
            expected_origin="https://login.example.com",
            pem_root_certs_bytes_by_fmt=PEM_ROOT_CERTS_BY_FMT,
            # Reject "none", self attestation, and chains that do not reach a configured root
            attestation_policy=AttestationPolicy.REQUIRE_TRUSTED_ROOT,
        )
    except InvalidRegistrationResponse as err:
        # A policy rejection (or any other verification failure) lands here
        raise PermissionError(f"Device is not enterprise-trusted: {err}") from err

    # No guesswork: the result itself documents the trust that was established
    assert verification.attestation_type == AttestationType.ATT_CA
    assert verification.trust_root_verified is True
    assert verification.trust_root_fingerprint is not None

    return {
        "credential_id": verification.credential_id,
        "credential_public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
        "aaguid": verification.aaguid,
        # Record which trust anchor vouched for this device
        "attestation_type": verification.attestation_type.value,
        "trust_root_fingerprint": verification.trust_root_fingerprint,
    }


def register_with_looser_policy(credential: dict, expected_challenge: bytes) -> dict:
    """Allow self attestation but still reject devices that send no attestation at all."""
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="login.example.com",
        expected_origin="https://login.example.com",
        pem_root_certs_bytes_by_fmt=PEM_ROOT_CERTS_BY_FMT,
        attestation_policy=AttestationPolicy.ALLOW_SELF,
    )

    # Branch on the reported attestation type instead of the format name
    if verification.trust_root_verified:
        trust_level = "enterprise-root"
    elif verification.attestation_type == AttestationType.SELF:
        trust_level = "self-attested"
    else:
        trust_level = "basic-unanchored"

    return {
        "credential_id": verification.credential_id,
        "trust_level": trust_level,
        "trust_root_fingerprint": verification.trust_root_fingerprint,
    }
