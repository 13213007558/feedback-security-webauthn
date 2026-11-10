import json
from json.decoder import JSONDecodeError
from typing import Any, Dict, Optional, Union

from .exceptions import InvalidAuthenticationResponse, InvalidJSONStructure
from .base64url_to_bytes import base64url_to_bytes
from .strict import (
    strict_base64url_to_bytes,
    strict_json_loads,
    validate_authentication_credential_dict,
)
from .structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttachment,
    PublicKeyCredentialType,
)


def parse_authentication_credential_json(
    json_val: Union[str, Dict[str, Any]],
    *,
    strict: bool = False,
) -> AuthenticationCredential:
    """
    Parse a JSON form of an authentication credential, as either a stringified JSON object or a
    plain dict, into an instance of AuthenticationCredential.

    With `strict=True` the same structural constraints are enforced for both entry shapes: raw JSON
    strings are checked for duplicate keys (including nested keys) while still being decoded, and
    both shapes undergo identical type, required-field, Base64URL, and id/rawId consistency checks.
    """
    if strict:
        return _parse_strict(json_val)

    if isinstance(json_val, str):
        try:
            json_val = json.loads(json_val)
        except JSONDecodeError:
            raise InvalidJSONStructure("Unable to decode credential as JSON")

    if not isinstance(json_val, dict):
        raise InvalidJSONStructure("Credential was not a JSON object")

    cred_id = json_val.get("id")
    if not isinstance(cred_id, str):
        raise InvalidJSONStructure("Credential missing required id")

    cred_raw_id = json_val.get("rawId")
    if not isinstance(cred_raw_id, str):
        raise InvalidJSONStructure("Credential missing required rawId")

    cred_response = json_val.get("response")
    if not isinstance(cred_response, dict):
        raise InvalidJSONStructure("Credential missing required response")

    response_client_data_json = cred_response.get("clientDataJSON")
    if not isinstance(response_client_data_json, str):
        raise InvalidJSONStructure("Credential response missing required clientDataJSON")

    response_authenticator_data = cred_response.get("authenticatorData")
    if not isinstance(response_authenticator_data, str):
        raise InvalidJSONStructure("Credential response missing required authenticatorData")

    response_signature = cred_response.get("signature")
    if not isinstance(response_signature, str):
        raise InvalidJSONStructure("Credential response missing required signature")

    cred_type = json_val.get("type")
    try:
        # Simply try to get the single matching Enum. We'll set the literal value below assuming
        # the code can get past here (this is basically a mypy optimization)
        PublicKeyCredentialType(cred_type)
    except ValueError as cred_type_exc:
        raise InvalidJSONStructure("Credential had unexpected type") from cred_type_exc

    response_user_handle = cred_response.get("userHandle")
    if isinstance(response_user_handle, str):
        # The `userHandle` string will most likely be base64url-encoded for ease of JSON
        # transmission as per the L3 Draft spec:
        # https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
        response_user_handle = base64url_to_bytes(response_user_handle)
    elif response_user_handle is not None:
        # If it's not a string, and it's not None, then it's definitely not valid
        raise InvalidJSONStructure("Credential response had unexpected userHandle")

    cred_authenticator_attachment = json_val.get("authenticatorAttachment")
    if isinstance(cred_authenticator_attachment, str):
        try:
            cred_authenticator_attachment = AuthenticatorAttachment(cred_authenticator_attachment)
        except ValueError as cred_attachment_exc:
            raise InvalidJSONStructure(
                "Credential had unexpected authenticatorAttachment"
            ) from cred_attachment_exc
    else:
        cred_authenticator_attachment = None

    try:
        authentication_credential = AuthenticationCredential(
            id=cred_id,
            raw_id=base64url_to_bytes(cred_raw_id),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(response_client_data_json),
                authenticator_data=base64url_to_bytes(response_authenticator_data),
                signature=base64url_to_bytes(response_signature),
                user_handle=response_user_handle,
            ),
            authenticator_attachment=cred_authenticator_attachment,
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
    except Exception as exc:
        raise InvalidAuthenticationResponse(
            "Could not parse authentication credential from JSON data. See __cause__ for more info"
        ) from exc

    return authentication_credential


def _parse_strict(
    json_val: Union[str, Dict[str, Any]],
) -> AuthenticationCredential:
    # `strict_json_loads` raises on duplicate keys for raw JSON; a dict is returned as-is since its
    # duplicates could no longer be recovered.
    credential_dict = strict_json_loads(json_val)

    # Equivalent type, required-field, encoding, and id/rawId consistency checks apply to both.
    validate_authentication_credential_dict(credential_dict)

    response = credential_dict["response"]

    user_handle: Optional[bytes] = None
    if response.get("userHandle") is not None:
        user_handle = strict_base64url_to_bytes(
            response["userHandle"], "response.userHandle"
        )

    attachment = credential_dict.get("authenticatorAttachment")
    authenticator_attachment: Optional[AuthenticatorAttachment] = (
        AuthenticatorAttachment(attachment) if attachment is not None else None
    )

    # Decode the Base64URL transport fields. The original clientDataJSON bytes are preserved
    # verbatim (only decoded, never re-encoded) so signature calculation later uses exact bytes.
    return AuthenticationCredential(
        id=credential_dict["id"],
        raw_id=strict_base64url_to_bytes(credential_dict["rawId"], "rawId"),
        response=AuthenticatorAssertionResponse(
            client_data_json=strict_base64url_to_bytes(
                response["clientDataJSON"], "response.clientDataJSON"
            ),
            authenticator_data=strict_base64url_to_bytes(
                response["authenticatorData"], "response.authenticatorData"
            ),
            signature=strict_base64url_to_bytes(
                response["signature"], "response.signature"
            ),
            user_handle=user_handle,
        ),
        authenticator_attachment=authenticator_attachment,
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )
