import hashlib
import json
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn import verify_authentication_response
from webauthn.helpers import bytes_to_base64url, encode_cbor
from webauthn.helpers.structs import SignCountPolicy

################
#
# Example of verifying authentications from a synced passkey whose sign count is
# not guaranteed to increase, and of persisting the new count safely when two
# concurrent requests read the same stored count.
#
################

# --- A locally generated credential standing in for a registered passkey ---
private_key = ec.generate_private_key(ec.SECP256R1())
public_numbers = private_key.public_key().public_numbers()
credential_public_key = encode_cbor(
    {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: public_numbers.x.to_bytes(32, "big"),
        -3: public_numbers.y.to_bytes(32, "big"),
    }
)
credential_id = b"synced-passkey-credential-id"
challenge = b"example-challenge"


def make_response(sign_count: int) -> str:
    """Build an authentication response the way a synced passkey would"""
    rp_id_hash = hashlib.sha256(b"localhost").digest()
    flags = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4)  # UP | UV | BE | BS
    auth_data = rp_id_hash + bytes([flags]) + sign_count.to_bytes(4, "big")
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": bytes_to_base64url(challenge),
            "origin": "http://localhost:5000",
            "crossOrigin": False,
        }
    ).encode("utf-8")
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )
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


# --- RP-side storage ---
db = sqlite3.connect(":memory:")
db.execute(
    "CREATE TABLE credentials (id BLOB PRIMARY KEY, public_key BLOB, sign_count INTEGER)"
)
db.execute(
    "INSERT INTO credentials VALUES (?, ?, ?)",
    (credential_id, credential_public_key, 10),
)
db.commit()


def verify_and_store(response_json: str) -> None:
    """Verify a response, then persist the counter without letting a slower
    concurrent request overwrite a newer count"""
    # Both concurrent requests read the same stored count here...
    stored_count = db.execute(
        "SELECT sign_count FROM credentials WHERE id = ?", (credential_id,)
    ).fetchone()[0]

    verification = verify_authentication_response(
        credential=response_json,
        expected_challenge=challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:5000",
        credential_public_key=credential_public_key,
        credential_current_sign_count=stored_count,
        sign_count_policy=SignCountPolicy.REPORT,
    )

    assessment = verification.sign_count_assessment
    if assessment.is_risk:
        # The response is cryptographically valid, but the counter did not
        # increase. The RP decides: log, require step-up auth, or reject.
        print(f"  risk detected: {assessment.reasons[0]}")

    # ...so the update must be conditional: only move the counter forward. If a
    # concurrent request already stored an equal-or-higher count, rowcount is 0
    # and this transaction must not overwrite the newer state.
    with db:
        cursor = db.execute(
            "UPDATE credentials SET sign_count = ? WHERE id = ? AND sign_count < ?",
            (verification.new_sign_count, credential_id, verification.new_sign_count),
        )
        if cursor.rowcount == 0:
            print(
                f"  skipped stale update to {verification.new_sign_count}: a newer"
                " count was already stored"
            )
            return
    print(f"  stored sign count {verification.new_sign_count}")


# Two requests race: both read stored count 10, then report counts 12 and 11.
# The slower request (11) finishes last but must not clobber the newer count (12).
print("Request A (count 12) finishes first:")
verify_and_store(make_response(sign_count=12))

print("Request B (count 11) finishes second:")
verify_and_store(make_response(sign_count=11))

final_count = db.execute(
    "SELECT sign_count FROM credentials WHERE id = ?", (credential_id,)
).fetchone()[0]
print(f"\nFinal stored count: {final_count}")
assert final_count == 12
