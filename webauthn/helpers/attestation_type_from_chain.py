from .structs import AttestationType, CertificateChainValidation


def attestation_type_from_chain(
    chain_validation: CertificateChainValidation,
) -> AttestationType:
    """Map a certificate chain validation outcome to an attestation type.

    A chain anchored to a configured trust root is attestation CA attestation; otherwise the
    signature was still verified but the certificate's source remains untrusted (basic).
    """
    if chain_validation.trust_root_verified:
        return AttestationType.ATT_CA
    return AttestationType.BASIC
