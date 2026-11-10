import json
from json.decoder import JSONDecodeError

from .base64url_to_bytes import base64url_to_bytes
from .byteslike_to_bytes import byteslike_to_bytes
from .exceptions import InvalidJSONStructure, StrictValidationError
from .strict import (
    require_bool,
    require_type,
    strict_base64url_to_bytes,
    strict_json_loads,
)
from .structs import CollectedClientData, TokenBinding, TokenBindingStatus


def parse_client_data_json(val: bytes, *, strict: bool = False) -> CollectedClientData:
    """
    Break apart `response.clientDataJSON` buffer into structured data.

    When `strict` is enabled the raw bytes are decoded with duplicate-key detection, booleans are
    not coerced from strings or numbers, and `challenge`/`origin`/`type` are checked against their
    expected types and encoding rules. The original bytes are returned untouched by the caller and
    used directly for signature calculation - this function never re-encodes them.
    """
    val = byteslike_to_bytes(val)

    if strict:
        return _parse_strict(val)

    try:
        json_dict = json.loads(val)
    except JSONDecodeError:
        raise InvalidJSONStructure("Unable to decode clientDataJSON bytes as JSON")

    if type(json_dict) is not dict:
        raise InvalidJSONStructure("clientDataJSON was not a dict")

    # Ensure required values are present in client data
    if "type" not in json_dict:
        raise InvalidJSONStructure('clientDataJSON missing required property "type"')
    if "challenge" not in json_dict:
        raise InvalidJSONStructure('clientDataJSON missing required property "challenge"')
    if "origin" not in json_dict:
        raise InvalidJSONStructure('clientDataJSON missing required property "origin"')

    client_data = CollectedClientData(
        type=json_dict["type"],
        challenge=base64url_to_bytes(json_dict["challenge"]),
        origin=json_dict["origin"],
    )

    # Populate optional values if set
    if "crossOrigin" in json_dict:
        cross_origin = bool(json_dict["crossOrigin"])
        client_data.cross_origin = cross_origin

    if "tokenBinding" in json_dict:
        token_binding_dict = json_dict["tokenBinding"]

        # Some U2F devices set a string to `token_binding`, in which case ignore it
        if type(token_binding_dict) is dict:
            if "status" not in token_binding_dict:
                raise InvalidJSONStructure('token_binding missing required property "status"')

            status = token_binding_dict["status"]
            try:
                # This will raise ValidationError on an unexpected status
                token_binding = TokenBinding(status=status)

                # Handle optional values
                if "id" in token_binding_dict:
                    id = token_binding_dict["id"]
                    token_binding.id = f"{id}"

                client_data.token_binding = token_binding
            except Exception:
                # If we encounter a status we don't expect then ignore token_binding
                # completely
                pass

    return client_data


def _parse_strict(val: bytes) -> CollectedClientData:
    # Duplicate keys (including in nested objects) are caught here, before a dict exists.
    json_dict = strict_json_loads(val)

    client_type = require_type(json_dict.get("type"), str, "type")
    challenge = strict_base64url_to_bytes(
        require_type(json_dict.get("challenge"), str, "challenge"),
        "challenge",
    )
    origin = require_type(json_dict.get("origin"), str, "origin")

    client_data = CollectedClientData(
        type=client_type,
        challenge=challenge,
        origin=origin,
    )

    if "crossOrigin" in json_dict:
        # A real boolean is required: "false"/"true" strings and 0/1 are rejected.
        client_data.cross_origin = require_bool(
            json_dict.get("crossOrigin"), "crossOrigin"
        )

    if "tokenBinding" in json_dict:
        token_binding_dict = json_dict["tokenBinding"]
        if type(token_binding_dict) is not dict:
            raise StrictValidationError(
                "Expected a JSON object", field="tokenBinding"
            )

        status = require_type(
            token_binding_dict.get("status"), str, "tokenBinding.status"
        )
        try:
            token_binding = TokenBinding(status=TokenBindingStatus(status))
        except ValueError as exc:
            raise StrictValidationError(
                "Unexpected tokenBinding status", field="tokenBinding.status"
            ) from exc

        if "id" in token_binding_dict:
            token_binding.id = require_type(
                token_binding_dict.get("id"), str, "tokenBinding.id", required=False
            )

        client_data.token_binding = token_binding

    # Unknown keys (e.g. future extensions) are ignored, never used to override known fields.
    return client_data
