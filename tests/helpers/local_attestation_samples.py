"""Deterministic, locally-generated WebAuthn registration samples.

These helpers build complete registration credentials without any external authenticator or
network access so that the full `verify_registration_response()` entry point can be exercised
against the four attestation trust situations that matter to an RP:

- "none" attestation (no signature, no trust)
- packed self attestation (credential key signs for itself)
- packed attestation with a chain to a configured trust root
- the same packed chain, but with that root not configured for the format
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from webauthn.helpers.cose import COSEAlgorithmIdentifier, COSECRV, COSEKTY, COSEKey

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
CHALLENGE = b"local-sample-challenge-0123456789"
CREDENTIAL_ID = b"local-credential-id-0001"
AAGUID = b"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"
ES256 = COSEAlgorithmIdentifier.ECDSA_SHA_256


@dataclass
class LocalSample:
    """A self-contained registration credential plus the data needed to verify it."""

    credential: Dict[str, object]
    expected_challenge: bytes
    expected_rp_id: str
    expected_origin: str
    root_cert_pem: Optional[bytes]
    trust_root_fingerprint: Optional[str]


def _base64url(val: bytes) -> str:
    return base64.urlsafe_b64encode(val).decode("utf-8").rstrip("=")


def _client_data_json() -> bytes:
    return json.dumps(
        {
            "type": "webauthn.create",
            "challenge": _base64url(CHALLENGE),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _cose_es256_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    cose_key = {
        COSEKey.KTY: COSEKTY.EC2,
        COSEKey.ALG: ES256,
        COSEKey.CRV: COSECRV.P256,
        COSEKey.X: numbers.x.to_bytes(32, "big"),
        COSEKey.Y: numbers.y.to_bytes(32, "big"),
    }
    return cbor2.dumps(cose_key)


def _authenticator_data(credential_public_key: bytes) -> bytes:
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    # UP and AT set; UV/BE/BS/ED clear
    flags = bytes([0x41])
    sign_count = (0).to_bytes(4, "big")
    attested_credential_data = (
        AAGUID
        + len(CREDENTIAL_ID).to_bytes(2, "big")
        + CREDENTIAL_ID
        + credential_public_key
    )
    return rp_id_hash + flags + sign_count + attested_credential_data


def _packed_signature_base(authenticator_data: bytes, client_data_json: bytes) -> bytes:
    return authenticator_data + hashlib.sha256(client_data_json).digest()


def _credential_dict(attestation_object: bytes, client_data_json: bytes) -> Dict[str, object]:
    return {
        "id": _base64url(CREDENTIAL_ID),
        "rawId": _base64url(CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "attestationObject": _base64url(attestation_object),
            "clientDataJSON": _base64url(client_data_json),
        },
    }


def _finalize(
    attestation_object: bytes,
    client_data_json: bytes,
    root_cert_pem: Optional[bytes],
    trust_root_fingerprint: Optional[str],
) -> LocalSample:
    return LocalSample(
        credential=_credential_dict(attestation_object, client_data_json),
        expected_challenge=CHALLENGE,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        root_cert_pem=root_cert_pem,
        trust_root_fingerprint=trust_root_fingerprint,
    )


def build_none_sample() -> LocalSample:
    """A "none" attestation: empty attStmt and no signature at all."""
    credential_key = ec.generate_private_key(ec.SECP256R1())
    auth_data = _authenticator_data(_cose_es256_public_key(credential_key.public_key()))
    attestation_object = cbor2.dumps(
        {
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        }
    )
    return _finalize(attestation_object, _client_data_json(), None, None)


def build_self_attestation_sample() -> LocalSample:
    """A packed self attestation: the credential private key signs for its own public key."""
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_public_key_cbor = _cose_es256_public_key(credential_key.public_key())
    auth_data = _authenticator_data(credential_public_key_cbor)
    client_data_json = _client_data_json()

    signature = credential_key.sign(
        _packed_signature_base(auth_data, client_data_json),
        ec.ECDSA(hashes.SHA256()),
    )

    attestation_object = cbor2.dumps(
        {
            "fmt": "packed",
            "attStmt": {"alg": ES256, "sig": signature},
            "authData": auth_data,
        }
    )
    return _finalize(attestation_object, client_data_json, None, None)


def _generate_root_ca() -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate, bytes]:
    root_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test Trust"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local Test Attestation Root"),
        ]
    )
    now = datetime.now(timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    fingerprint = root_cert.fingerprint(hashes.SHA256()).hex(":").upper()
    return root_key, root_cert, root_pem, fingerprint


def _generate_leaf_cert(
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test Authenticator"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local Test Attestation Leaf"),
        ]
    )
    now = datetime.now(timezone.utc)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    return leaf_key, leaf_cert


def build_packed_chain_sample() -> LocalSample:
    """Packed attestation whose x5c chain is anchored by a locally generated trust root."""
    root_key, root_cert, root_pem, fingerprint = _generate_root_ca()
    leaf_key, leaf_cert = _generate_leaf_cert(root_key, root_cert)

    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_public_key_cbor = _cose_es256_public_key(credential_key.public_key())
    auth_data = _authenticator_data(credential_public_key_cbor)
    client_data_json = _client_data_json()

    # The attestation signature is produced by the attestation leaf certificate's key
    signature = leaf_key.sign(
        _packed_signature_base(auth_data, client_data_json),
        ec.ECDSA(hashes.SHA256()),
    )

    attestation_object = cbor2.dumps(
        {
            "fmt": "packed",
            "attStmt": {
                "alg": ES256,
                "sig": signature,
                "x5c": [leaf_cert.public_bytes(serialization.Encoding.DER)],
            },
            "authData": auth_data,
        }
    )
    return _finalize(attestation_object, client_data_json, root_pem, fingerprint)


def build_all_samples() -> List[LocalSample]:
    return [
        build_none_sample(),
        build_self_attestation_sample(),
        build_packed_chain_sample(),
    ]
