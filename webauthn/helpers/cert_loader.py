"""Lenient X.509 certificate loading helpers.

The certificate chains that show up in WebAuthn attestation statements are not
always strict DER. Real-world Android Keystore attestation certificates exist
that encode an X.509 ``Extension.critical`` field as an explicit ``FALSE``
value, which violates the DER rule that a BOOLEAN DEFAULT FALSE must be
omitted when false. The OpenSSL-based stack accepted these because OpenSSL's
certificate parser tolerates BER.

``cryptography``'s parser is strict DER and rejects such certificates, so we
re-parse through the BER decoder (already a dependency for Android Key
attestation parsing) and re-encode to canonical DER before handing the bytes
to ``cryptography``. Only an encoding mismatch is repaired: BER decoding
preserves every field, OID and value of the certificate.

Signature verification needs care. An X.509 signature is computed over the
``tbsCertificate`` TLV exactly as encoded in the original bytes. Re-encoding a
BER certificate to DER can change those bytes (for example by stripping the
explicit default BOOLEAN), so the signature must be checked against the
original TLV. :class:`ParsedCertificate` keeps both the parsed
``cryptography`` certificate and the original ``tbsCertificate`` bytes.
"""

from dataclasses import dataclass
from typing import Tuple

from cryptography.x509 import Certificate, load_der_x509_certificate
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules.rfc5280 import Certificate as Pyasn1Certificate


@dataclass(frozen=True)
class ParsedCertificate:
    """A parsed certificate paired with its originally signed TBS bytes."""

    cert: Certificate
    tbs_bytes: bytes


def _read_tlv(data: bytes, offset: int) -> Tuple[int, int, int]:
    """Read one DER/BER TLV header, returning (tag, content_offset, length)."""
    tag = data[offset]
    offset += 1
    first_length_octet = data[offset]
    offset += 1
    if first_length_octet & 0x80:
        num_length_octets = first_length_octet & 0x7F
        length = int.from_bytes(
            data[offset : offset + num_length_octets],
            byteorder="big",
        )
        offset += num_length_octets
    else:
        length = first_length_octet
    return tag, offset, length


def extract_tbs_certificate_bytes(cert_bytes: bytes) -> bytes:
    """Return the full ``tbsCertificate`` TLV, exactly as originally encoded."""
    _, outer_content_offset, _ = _read_tlv(cert_bytes, 0)
    _, tbs_content_offset, tbs_length = _read_tlv(
        cert_bytes,
        outer_content_offset,
    )
    tbs_tlv_start = outer_content_offset
    tbs_tlv_end = tbs_content_offset + tbs_length
    return cert_bytes[tbs_tlv_start:tbs_tlv_end]


def _load_strict_der(cert_bytes: bytes) -> Certificate:
    return load_der_x509_certificate(cert_bytes)


def _normalize_ber_to_der(cert_bytes: bytes) -> bytes:
    parsed_cert, trailing_bytes = ber_decoder.decode(
        cert_bytes,
        asn1Spec=Pyasn1Certificate(),
    )
    if trailing_bytes:
        raise ValueError(
            "Certificate bytes contained trailing data after BER decoding"
        )
    return der_encoder.encode(parsed_cert)


def load_x509_cert_with_ber_fallback(cert_bytes: bytes) -> ParsedCertificate:
    """Load an X.509 certificate, tolerating BER-encoded input.

    Strict DER is attempted first. On failure, the bytes are decoded as BER and
    re-encoded to canonical DER so ``cryptography`` can parse them. The
    returned object always carries the ``tbsCertificate`` bytes from the
    original input for signature verification.

    Raises ``ValueError`` if the bytes cannot be parsed as an X.509 certificate.
    """
    original_tbs_bytes = extract_tbs_certificate_bytes(cert_bytes)
    try:
        cert = _load_strict_der(cert_bytes)
    except ValueError:
        cert = _load_strict_der(_normalize_ber_to_der(cert_bytes))
    return ParsedCertificate(cert=cert, tbs_bytes=original_tbs_bytes)
