from datetime import datetime
from typing import List, Optional

from .certificate_chain_verifier import (
    CertificateChainVerificationError,
    verify_certificate_chain,
)
from .exceptions import InvalidCertificateChain


def _get_verification_time() -> Optional[datetime]:
    """Return the fixed instant to validate certificate validity against.

    Returning ``None`` means validation uses the current system time. Tests
    patch this function to pin verification to a point in the past so that
    certificates captured in test fixtures can still be fully validated after
    their real-world expiration.
    """
    return None


def validate_certificate_chain(
    *,
    x5c: List[bytes],
    pem_root_certs_bytes: Optional[List[bytes]] = None,
) -> bool:
    """Validate that the certificates in x5c chain back to a known root certificate

    Args:
        `x5c`: X5C certificates from a registration response's attestation statement
        (optional) `pem_root_certs_bytes`: Any additional (PEM-formatted)
        root certificates that may complete the certificate chain

    Raises:
        `helpers.exceptions.InvalidCertificateChain` if chain cannot be validated
    """
    if pem_root_certs_bytes is None or len(pem_root_certs_bytes) < 1:
        # We have no root certs to chain back to, so just pass on validation.
        # This preserves the library's long-standing behavior: with no trust
        # anchors configured there is nothing to validate against, and the
        # attestation format verifiers are responsible for their own root
        # pinning. No chain has been validated when this returns.
        return True

    # Make sure we have at least one certificate to try and link back to a root cert
    if len(x5c) < 1:
        raise InvalidCertificateChain("x5c was empty")

    try:
        verify_certificate_chain(
            x5c=x5c,
            pem_root_certs_bytes=pem_root_certs_bytes,
            verification_time=_get_verification_time(),
        )
    except CertificateChainVerificationError as exc:
        raise InvalidCertificateChain(
            "Certificate chain could not be validated. See __cause__ for more info"
        ) from exc

    return True
