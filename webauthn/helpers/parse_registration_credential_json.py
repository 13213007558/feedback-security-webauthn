import json
from json.decoder import JSONDecodeError
from typing import Any, Dict, Union, Optional, List

from .base64url_to_bytes import base64url_to_bytes
from .exceptions import InvalidRegistrationResponse, InvalidJSONStructure
from .strict import (
    strict_base64url_to_bytes,
    strict_json_loads,
    validate_registration_credential_dict,
)
from .structs import (
    AuthenticatorAttachment,
    AuthenticatorAttestationResponse,
    AuthenticatorTransport,
    PublicKeyCredentialType,
    RegistrationCredential,
)


def parse_registration_credential_json(
    json_val: Union[str, Dict[str, Any]],
    *,
    strict: bool = False,
) -> RegistrationCredential:
    """
    Parse a JSON form of a registration credential, as either a stringified JSON object or a
    plain dict, into an instance of RegistrationCredential.

    With `strict=True` raw JSON strings are decoded while rejecting duplicate keys (including in
    nested objects), and both string and dict inputs undergo identical type, required-field,
    Base64URL, and id/rawId consistency checks.
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

    response_attestation_object = cred_response.get("attestationObject")
    if not isinstance(response_attestation_object, str):
        raise InvalidJSONStructure("Credential response missing required attestationObject")

    cred_type = json_val.get("type")
    try:
        # Simply try to get the single matching Enum. We'll set the literal value below assuming
        # the code can get past here (this is basically a mypy optimization)
        PublicKeyCredentialType(cred_type)
    except ValueError as cred_type_exc:
        raise InvalidJSONStructure("Credential had unexpected type") from cred_type_exc

    transports: Optional[List[AuthenticatorTransport]] = None
    response_transports = cred_response.get("transports")
    if isinstance(response_transports, list):
        transports = []
        for val in response_transports:
            try:
                transport_enum = AuthenticatorTransport(val)
                transports.append(transport_enum)
            except ValueError:
                pass

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
        registration_credential = RegistrationCredential(
            id=cred_id,
            raw_id=base64url_to_bytes(cred_raw_id),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(response_client_data_json),
                attestation_object=base64url_to_bytes(response_attestation_object),
                transports=transports,
            ),
            authenticator_attachment=cred_authenticator_attachment,
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )
    except Exception as exc:
        raise InvalidRegistrationResponse(
            "Could not parse registration credential from JSON data. See __cause__ for more info"
        ) from exc

    return registration_credential


def _parse_strict(json_val: Union[str, Dict[str, Any]]) -> RegistrationCredential:
    # Duplicate keys are caught during decoding for raw JSON; dicts cannot recover them.
    credential_dict = strict_json_loads(json_val)

    # Same structural validation for both shapes.
    validate_registration_credential_dict(credential_dict)

    response = credential_dict["response"]

    transports: Optional[List[AuthenticatorTransport]] = None
    if response.get("transports") is not None:
        transports = [AuthenticatorTransport(val) for val in response["transports"]]

    attachment = credential_dict.get("authenticatorAttachment")
    authenticator_attachment: Optional[AuthenticatorAttachment] = (
        AuthenticatorAttachment(attachment) if attachment is not None else None
    )

    # The original clientDataJSON bytes are only decoded, never re-encoded.
    return RegistrationCredential(
        id=credential_dict["id"],
        raw_id=strict_base64url_to_bytes(credential_dict["rawId"], "rawId"),
        response=AuthenticatorAttestationResponse(
            client_data_json=strict_base64url_to_bytes(
                response["clientDataJSON"], "response.clientDataJSON"
            ),
            attestation_object=strict_base64url_to_bytes(
                response["attestationObject"], "response.attestationObject"
            ),
            transports=transports,
        ),
        authenticator_attachment=authenticator_attachment,
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )
