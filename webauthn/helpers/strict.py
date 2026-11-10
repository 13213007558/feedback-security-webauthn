"""
Strict parsing primitives shared by the registration and authentication credential parsers.

The default, lenient parsing behavior of this library is preserved. When strict parsing is opted
into, the same structural constraints are applied no matter whether the input arrives as a JSON
string, a dict, or an already-constructed credential object:

- duplicate security-relevant keys in raw JSON (including in nested objects) are detected while
  the bytes are still being decoded, before Python's `json` module can silently collapse them;
- booleans must be real booleans (strings and numbers are not coerced);
- `id`/`rawId`, `challenge`, and the binary transport fields are checked against their expected
  types and Base64URL encoding rules;
- unknown/extension fields are left untouched and never overwrite known fields.

Error messages only mention field paths and expected types. Sensitive values (challenges,
signatures, user handles) are never included.
"""

import json
from json.decoder import JSONDecodeError
import re
from typing import Any, Dict, List, Tuple, Union

from .base64url_to_bytes import base64url_to_bytes
from .byteslike_to_bytes import byteslike_to_bytes
from .bytes_to_base64url import bytes_to_base64url
from .exceptions import StrictValidationError
from .structs import (
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorTransport,
    PublicKeyCredentialType,
    RegistrationCredential,
)

# Unpadded Base64URL alphabet, per RFC 4648 section 5 ("base64url" without "=" padding)
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def strict_json_loads(raw: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Decode a raw JSON document into a plain dict while rejecting duplicate object keys at every
    nesting level. A dict/object input cannot be re-inspected for duplicates (they were already
    collapsed by the time it reached us), so it is handed back for structural validation instead.
    """
    if isinstance(raw, dict):
        return raw

    if not isinstance(raw, (str, bytes)):
        raise StrictValidationError("Expected a JSON object, string, or bytes")

    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictValidationError("Value was not valid UTF-8 JSON") from exc
    else:
        text = raw

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_DuplicateKeyDetector(),
        )
    except StrictValidationError:
        raise
    except JSONDecodeError as exc:
        raise StrictValidationError("Unable to decode value as JSON") from exc

    if not isinstance(decoded, dict):
        raise StrictValidationError("Value was not a JSON object")

    return decoded


class _DuplicateKeyDetector:
    """
    `object_pairs_hook` that sees every key/value pair in document order, including duplicates,
    before they are collapsed into a dict. Raising on the first repeated key means ambiguity is
    caught before a dict ever exists. Nested objects are checked independently because the hook
    fires bottom-up for each object in the document.
    """

    def __call__(self, pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        seen = set()
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise StrictValidationError(
                    "Duplicate key found while parsing JSON",
                    field=str(key),
                )
            seen.add(key)
            result[key] = value
        return result


def strict_base64url_to_bytes(val: Any, field: str) -> bytes:
    """
    Decode an unpadded Base64URL string into bytes, rejecting non-strings and any character or
    length that the lenient decoder would otherwise tolerate.
    """
    if not isinstance(val, str):
        raise StrictValidationError(
            "Expected a Base64URL-encoded string",
            field=field,
        )

    if not _BASE64URL_RE.match(val):
        raise StrictValidationError(
            "Value was not valid unpadded Base64URL",
            field=field,
        )

    # A Base64URL string can never have a length of 1 modulo 4 (there is no way to encode a lone
    # trailing byte); reject it rather than relying on decoder-specific behavior.
    if len(val) % 4 == 1:
        raise StrictValidationError(
            "Value had an invalid Base64URL length",
            field=field,
        )

    try:
        return base64url_to_bytes(val)
    except Exception as exc:
        raise StrictValidationError(
            "Value could not be Base64URL-decoded",
            field=field,
        ) from exc


def require_type(
    val: Any,
    expected: type,
    field: str,
    *,
    required: bool = True,
) -> Any:
    """
    Assert that `val` is exactly of `expected`. Using `type(...) is ...` (rather than
    `isinstance`) keeps booleans distinct from ints and rejects subclasses that would blur the
    JSON type contract.
    """
    if val is None:
        if required:
            raise StrictValidationError("Missing required field", field=field)
        return None

    if type(val) is not expected:
        raise StrictValidationError(
            f"Expected {expected.__name__}",
            field=field,
        )

    return val


def require_bool(val: Any, field: str, *, required: bool = False) -> Any:
    """A JSON boolean must be an actual bool; strings like "false" or 0/1 are not accepted."""
    if val is None:
        if required:
            raise StrictValidationError("Missing required field", field=field)
        return None

    if type(val) is not bool:
        raise StrictValidationError("Expected a boolean", field=field)

    return val


def _require_response_object(credential: Dict[str, Any]) -> Dict[str, Any]:
    response = credential.get("response")
    if type(response) is not dict:
        raise StrictValidationError(
            "Expected a JSON object", field="response"
        )
    return response


def _validate_credential_wrapper(credential: Dict[str, Any]) -> None:
    """
    Checks shared by registration and authentication credential wrappers. Unknown keys (e.g.
    `clientExtensionResults`) are intentionally ignored and never override known fields.
    """
    cred_id = require_type(credential.get("id"), str, "id")
    if not cred_id:
        raise StrictValidationError("Expected a non-empty string", field="id")
    raw_id = require_type(credential.get("rawId"), str, "rawId")
    if not raw_id:
        raise StrictValidationError("Expected a non-empty string", field="rawId")
    response = _require_response_object(credential)

    # FIDO consistency: `id` is the Base64URL encoding of `rawId` and the two must describe the
    # same credential identifier.
    raw_id_bytes = strict_base64url_to_bytes(raw_id, "rawId")
    if bytes_to_base64url(raw_id_bytes) != cred_id:
        raise StrictValidationError(
            'Credential "id" and "rawId" were not equivalent',
            field="rawId",
        )

    cred_type = credential.get("type")
    if type(cred_type) is not str:
        raise StrictValidationError("Expected a string", field="type")
    try:
        PublicKeyCredentialType(cred_type)
    except ValueError as exc:
        raise StrictValidationError("Unexpected credential type", field="type") from exc

    attachment = credential.get("authenticatorAttachment")
    if attachment is not None:
        if type(attachment) is not str:
            raise StrictValidationError(
                "Expected a string", field="authenticatorAttachment"
            )
        try:
            AuthenticatorAttachment(attachment)
        except ValueError as exc:
            raise StrictValidationError(
                "Unexpected authenticatorAttachment",
                field="authenticatorAttachment",
            ) from exc

    # clientDataJSON is a Base64URL string at the wrapper level; the decoded bytes themselves are
    # parsed strictly later, during response verification.
    strict_base64url_to_bytes(
        require_type(response.get("clientDataJSON"), str, "response.clientDataJSON"),
        "response.clientDataJSON",
    )

    return response


def validate_registration_credential_dict(credential: Dict[str, Any]) -> None:
    response = _validate_credential_wrapper(credential)

    strict_base64url_to_bytes(
        require_type(
            response.get("attestationObject"),
            str,
            "response.attestationObject",
        ),
        "response.attestationObject",
    )

    transports = response.get("transports")
    if transports is not None:
        if type(transports) is not list:
            raise StrictValidationError(
                "Expected a list", field="response.transports"
            )
        for index, transport in enumerate(transports):
            field = f"response.transports[{index}]"
            if type(transport) is not str:
                raise StrictValidationError("Expected a string", field=field)
            try:
                AuthenticatorTransport(transport)
            except ValueError as exc:
                raise StrictValidationError(
                    "Unexpected authenticator transport", field=field
                ) from exc


def validate_authentication_credential_dict(credential: Dict[str, Any]) -> None:
    response = _validate_credential_wrapper(credential)

    strict_base64url_to_bytes(
        require_type(
            response.get("authenticatorData"),
            str,
            "response.authenticatorData",
        ),
        "response.authenticatorData",
    )
    strict_base64url_to_bytes(
        require_type(response.get("signature"), str, "response.signature"),
        "response.signature",
    )

    user_handle = response.get("userHandle")
    if user_handle is not None:
        # Optional, but when present it must be a Base64URL string rather than another type.
        strict_base64url_to_bytes(
            require_type(user_handle, str, "response.userHandle"),
            "response.userHandle",
        )


def validate_registration_credential_object(credential: RegistrationCredential) -> None:
    """
    Equivalent structural checks for an already-constructed object. Duplicate keys cannot be
    recovered at this stage, but types, required fields, and id/rawId consistency still apply.
    """
    if type(credential.id) is not str or not credential.id:
        raise StrictValidationError("Expected a non-empty string", field="id")

    _validate_bytes_field(credential.raw_id, "rawId")
    if bytes_to_base64url(byteslike_to_bytes(credential.raw_id)) != credential.id:
        raise StrictValidationError(
            'Credential "id" and "rawId" were not equivalent', field="rawId"
        )

    response = credential.response
    _validate_bytes_field(response.client_data_json, "response.clientDataJSON")
    _validate_bytes_field(response.attestation_object, "response.attestationObject")


def validate_authentication_credential_object(
    credential: AuthenticationCredential,
) -> None:
    if type(credential.id) is not str or not credential.id:
        raise StrictValidationError("Expected a non-empty string", field="id")

    _validate_bytes_field(credential.raw_id, "rawId")
    if bytes_to_base64url(byteslike_to_bytes(credential.raw_id)) != credential.id:
        raise StrictValidationError(
            'Credential "id" and "rawId" were not equivalent', field="rawId"
        )

    response = credential.response
    _validate_bytes_field(response.client_data_json, "response.clientDataJSON")
    _validate_bytes_field(response.authenticator_data, "response.authenticatorData")
    _validate_bytes_field(response.signature, "response.signature")

    if response.user_handle is not None:
        _validate_bytes_field(response.user_handle, "response.userHandle")


def _validate_bytes_field(val: Any, field: str) -> None:
    # bytes subclasses and memoryview remain supported (duck-typing), but nothing else is.
    if not isinstance(val, (bytes, bytearray, memoryview)):
        raise StrictValidationError("Expected bytes-like data", field=field)
