"""RFC 5280 certificate chain verification built on ``cryptography`` primitives.

This module replaces the previous pyOpenSSL ``X509Store``/``X509StoreContext``
based validation. The high-level ``cryptography.x509.verification`` API
(rust-webpki) cannot be used here because it is intentionally stricter than the
OpenSSL defaults this library relied on:

- rust-webpki forbids RSA PKCS#1 v1.5 certificate signatures, which every
  Google Android hardware attestation chain in the wild uses
  (``sha256WithRSAEncryption``).
- rust-webpki requires authority key identifier and subject alternative name
  extensions on end-entity certificates; attestation leaf certificates (e.g.
  Apple's WebAuthn attestation CA leaves) commonly contain neither.
- rust-webpki rejects unrecognized critical extensions; TPM attestation leaves
  carry a critical ``certificatePolicies`` extension.

Instead, chain construction and policy enforcement below are implemented
explicitly with public ``cryptography`` APIs, matching the checks the default
OpenSSL ``X509`` verification path performed:

- signature validity of every issuer -> subject link, over the subject's
  originally encoded ``tbsCertificate`` bytes
- certificate validity windows against an injectable verification instant
- basic constraints: every non-anchor CA in the path must assert ``cA=true``
- path length constraints (``basicConstraints.pathLen``)
- CA key usage (``keyCertSign`` must be asserted when ``keyUsage`` is present)
- critical extension recognition
- name constraints (``nameConstraints`` permitted/excluded subtrees)
- trust boundary: a chain is only accepted when it terminates at a
  self-asserted root supplied through the configured trust store

There is deliberately no EKU enforcement and no DNS SAN requirement:
attestation leaf certificates are not TLS server certificates and no hostname
is being authenticated.
"""

import ipaddress
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate
from cryptography.x509.general_name import (
    DNSName,
    DirectoryName,
    IPAddress,
    RFC822Name,
    RegisteredID,
    UniformResourceIdentifier,
)

from .cert_loader import (
    ParsedCertificate,
    extract_tbs_certificate_bytes,
    load_x509_cert_with_ber_fallback,
)


class CertificateChainVerificationError(Exception):
    """Raised when a certificate chain cannot be built or validated."""


# Extensions whose semantics are understood during chain validation. A critical
# extension outside this set cannot be honored and must fail the chain, the
# same way OpenSSL rejects unhandled critical extensions (X509_V_ERR code "h").
_RECOGNIZED_EXTENSION_TYPES: Tuple[type, ...] = (
    x509.BasicConstraints,
    x509.KeyUsage,
    x509.ExtendedKeyUsage,
    x509.SubjectKeyIdentifier,
    x509.AuthorityKeyIdentifier,
    x509.SubjectAlternativeName,
    x509.IssuerAlternativeName,
    x509.AuthorityInformationAccess,
    x509.CRLDistributionPoints,
    x509.CertificatePolicies,
    x509.NameConstraints,
    x509.PolicyConstraints,
    x509.InhibitAnyPolicy,
)

_MAX_PATH_SEARCH_DEPTH = 8


def _load_pem_or_der(cert_bytes: bytes) -> ParsedCertificate:
    if b"-----BEGIN" in cert_bytes:
        cert = x509.load_pem_x509_certificate(cert_bytes)
        der_bytes = cert.public_bytes(Encoding.DER)
        return ParsedCertificate(
            cert=cert,
            tbs_bytes=extract_tbs_certificate_bytes(der_bytes),
        )
    return load_x509_cert_with_ber_fallback(cert_bytes)


def _verification_instant(verification_time: Optional[datetime]) -> datetime:
    if verification_time is None:
        return datetime.now(tz=timezone.utc)
    if verification_time.tzinfo is None:
        return verification_time.replace(tzinfo=timezone.utc)
    return verification_time.astimezone(timezone.utc)


def _verify_signature(subject: ParsedCertificate, issuer: ParsedCertificate) -> None:
    """Verify that ``subject`` was signed by ``issuer``'s public key."""
    cert = subject.cert
    public_key = issuer.cert.public_key()
    tbs_bytes = subject.tbs_bytes
    signature = cert.signature
    hash_algorithm = cert.signature_hash_algorithm

    if isinstance(public_key, rsa.RSAPublicKey):
        if cert.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=hash_algorithm.digest_size
                    if hash_algorithm is not None
                    else padding.PSS.DIGEST_LENGTH,
                ),
                hash_algorithm,
            )
        else:
            # sha{1,256,384,512}WithRSAEncryption (RSA PKCS#1 v1.5)
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            signature,
            tbs_bytes,
            ec.ECDSA(hash_algorithm),
        )
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, tbs_bytes, hash_algorithm)
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        # PureEdDSA takes no separate digest and signs over the TBS directly.
        public_key.verify(signature, tbs_bytes)
    else:
        raise CertificateChainVerificationError(
            f"Unsupported issuer public key type {type(public_key).__name__}"
        )


def _check_validity_window(cert: Certificate, at_time: datetime) -> None:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if at_time < not_before or at_time > not_after:
        raise CertificateChainVerificationError(
            f"Certificate is not valid at verification time {at_time.isoformat()} "
            f"(valid {not_before.isoformat()} to {not_after.isoformat()})"
        )


def _check_critical_extensions(cert: Certificate) -> None:
    for extension in cert.extensions:
        if not extension.critical:
            continue
        if not isinstance(extension.value, _RECOGNIZED_EXTENSION_TYPES):
            raise CertificateChainVerificationError(
                f"Certificate contains an unrecognized critical extension "
                f"{extension.oid.dotted_string}"
            )


def _check_ca_constraints(cert: Certificate) -> None:
    try:
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as exc:
        raise CertificateChainVerificationError(
            "CA certificate is missing the basicConstraints extension"
        ) from exc
    if not basic_constraints.ca:
        raise CertificateChainVerificationError(
            "Certificate used as a CA does not assert cA=true in basicConstraints"
        )
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not key_usage.key_cert_sign:
        raise CertificateChainVerificationError(
            "CA certificate keyUsage does not permit keyCertSign"
        )


def _path_length(cert: Certificate) -> Optional[int]:
    try:
        return cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
    except x509.ExtensionNotFound:
        return None


def _issued_by(subject: ParsedCertificate, issuer: ParsedCertificate) -> bool:
    if subject.cert.issuer != issuer.cert.subject:
        return False
    try:
        _verify_signature(subject, issuer)
    except (InvalidSignature, ValueError):
        return False
    return True


def _dns_name_matches(pattern: str, name: str) -> bool:
    pattern = pattern.lower().strip()
    name = name.lower().strip()
    if pattern.startswith("."):
        return name == pattern[1:] or name.endswith(pattern)
    return name == pattern or name.endswith("." + pattern)


def _email_matches(pattern: str, name: str) -> bool:
    pattern = pattern.lower()
    name = name.lower()
    if pattern.startswith("."):
        return name.endswith(pattern)
    return name == pattern


def _directory_name_matches(constraint: x509.Name, name: x509.Name) -> bool:
    constraint_attrs = list(constraint)
    name_attrs = list(name)
    if len(constraint_attrs) > len(name_attrs):
        return False
    return all(
        name_attrs[index] == attribute
        for index, attribute in enumerate(constraint_attrs)
    )


def _general_name_satisfies_constraint(
    general_name: x509.GeneralName,
    constraint: x509.GeneralName,
) -> bool:
    if isinstance(general_name, DNSName) and isinstance(constraint, DNSName):
        return _dns_name_matches(constraint.value, general_name.value)
    if isinstance(general_name, RFC822Name) and isinstance(constraint, RFC822Name):
        return _email_matches(constraint.value, general_name.value)
    if isinstance(
        general_name, UniformResourceIdentifier
    ) and isinstance(constraint, UniformResourceIdentifier):
        return _dns_name_matches(constraint.value, general_name.value)
    if isinstance(general_name, IPAddress) and isinstance(constraint, IPAddress):
        try:
            return general_name.value.version == constraint.value.version and (
                general_name.value in constraint.value
            )
        except (TypeError, ipaddress.AddressValueError):
            return general_name.value == constraint.value
    if isinstance(general_name, DirectoryName) and isinstance(
        constraint, DirectoryName
    ):
        return _directory_name_matches(constraint.value, general_name.value)
    # Constraint types we cannot evaluate against this name type are not
    # enforced, matching OpenSSL's handling of unsupported name mismatches.
    return True


def _subject_general_names(cert: Certificate) -> List[x509.GeneralName]:
    names: List[x509.GeneralName] = []
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return names
    for general_name in san:
        if isinstance(
            general_name,
            (x509.OtherName, x509.UnsupportedGeneralNameType, RegisteredID),
        ):
            # Name constraints cannot be applied to these name forms; OpenSSL
            # only constrains DNS, email, URI, IP and directory names.
            continue
        names.append(general_name)
    return names


def _check_name_constraints(
    cert: Certificate, constraints: Sequence[x509.NameConstraints]
) -> None:
    if not constraints:
        return
    general_names = _subject_general_names(cert)
    for name_constraints in constraints:
        permitted = name_constraints.permitted_subtrees or []
        excluded = name_constraints.excluded_subtrees or []
        for general_name in general_names:
            for constraint in excluded:
                if not _general_name_satisfies_constraint(general_name, constraint):
                    continue
                raise CertificateChainVerificationError(
                    "Certificate subject name violates an excluded name constraint"
                )
            if permitted and not any(
                _general_name_satisfies_constraint(general_name, constraint)
                for constraint in permitted
            ):
                raise CertificateChainVerificationError(
                    "Certificate subject name is not within a permitted name constraint"
                )


def _build_chain(
    leaf: ParsedCertificate,
    intermediates: Sequence[ParsedCertificate],
    roots: Sequence[ParsedCertificate],
) -> List[ParsedCertificate]:
    """Construct a path from the leaf up to a configured trust anchor."""
    chain = [leaf]
    available = list(intermediates)
    while True:
        current = chain[-1]
        for root in roots:
            if _issued_by(current, root):
                chain.append(root)
                return chain
        next_index: Optional[int] = None
        for index, candidate in enumerate(available):
            if _issued_by(current, candidate):
                next_index = index
                break
        if next_index is None:
            raise CertificateChainVerificationError(
                "Could not build a certificate path to any trusted root"
            )
        chain.append(available.pop(next_index))
        if len(chain) > _MAX_PATH_SEARCH_DEPTH:
            raise CertificateChainVerificationError(
                "Certificate chain exceeded maximum path construction depth"
            )


def verify_certificate_chain(
    *,
    x5c: Sequence[bytes],
    pem_root_certs_bytes: Sequence[bytes],
    verification_time: Optional[datetime] = None,
) -> None:
    """Validate an attestation certificate chain against trusted root certs.

    Raises ``CertificateChainVerificationError`` on any validation failure.
    """
    if not x5c:
        raise CertificateChainVerificationError("x5c was empty")

    at_time = _verification_instant(verification_time)

    try:
        leaf = load_x509_cert_with_ber_fallback(x5c[0])
        intermediates = [
            load_x509_cert_with_ber_fallback(cert_bytes) for cert_bytes in x5c[1:]
        ]
        roots = [_load_pem_or_der(cert_bytes) for cert_bytes in pem_root_certs_bytes]
    except CertificateChainVerificationError:
        raise
    except Exception as exc:
        raise CertificateChainVerificationError(
            "Could not parse certificates for chain validation"
        ) from exc

    if not roots:
        raise CertificateChainVerificationError(
            "No trusted root certificates were configured"
        )

    chain = _build_chain(leaf, intermediates, roots)

    # Validity windows and critical extensions apply to every certificate,
    # including the trusted anchor.
    for parsed in chain:
        _check_validity_window(parsed.cert, at_time)
        _check_critical_extensions(parsed.cert)

    accumulated_constraints: List[x509.NameConstraints] = []
    # chain[-1] is the trust anchor. Enforce CA policy on every non-anchor
    # certificate that issues another one in the path; the anchor itself is
    # trusted by configuration rather than by its own basicConstraints,
    # matching OpenSSL, which does not apply CA constraints to the anchor.
    issuing_certificates = chain[1:-1]
    total_issuing_certificates = len(issuing_certificates)
    for depth, parsed in enumerate(reversed(issuing_certificates)):
        cert = parsed.cert
        _check_ca_constraints(cert)

        path_length = _path_length(cert)
        if path_length is not None:
            # RFC 5280 4.2.1.9: pathLenConstraint gives the maximum number of
            # non-self-issued intermediate CAs that may follow this certificate
            # in the chain. ``depth`` counts issuing CAs below this one (0 for
            # the CA that directly issues the leaf).
            intermediates_below = total_issuing_certificates - 1 - depth
            if intermediates_below > path_length:
                raise CertificateChainVerificationError(
                    "Certificate chain violates basicConstraints path length"
                )

        try:
            name_constraints = cert.extensions.get_extension_for_class(
                x509.NameConstraints
            ).value
        except x509.ExtensionNotFound:
            name_constraints = None
        if name_constraints is not None:
            accumulated_constraints.append(name_constraints)

    # Name constraints gathered from every CA above apply to the leaf.
    _check_name_constraints(leaf.cert, accumulated_constraints)
