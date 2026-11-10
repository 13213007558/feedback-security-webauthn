from typing import Optional


class WebAuthnException(Exception):
    pass


class InvalidRegistrationOptions(WebAuthnException):
    pass


class InvalidRegistrationResponse(WebAuthnException):
    pass


class InvalidAuthenticationOptions(WebAuthnException):
    pass


class InvalidAuthenticationResponse(WebAuthnException):
    pass


class InvalidPublicKeyStructure(WebAuthnException):
    pass


class UnsupportedPublicKeyType(WebAuthnException):
    pass


class InvalidJSONStructure(WebAuthnException):
    pass


class StrictValidationError(InvalidJSONStructure):
    """
    Raised when a credential or `clientDataJSON` cannot satisfy the stricter structural
    constraints of strict parsing (duplicate keys, unexpected types, invalid encodings, etc...).

    It subclasses `InvalidJSONStructure` so existing handlers that already catch malformed JSON
    keep working, while callers that opt into strict parsing can target it explicitly. Messages
    only ever reference field paths and expected types, never sensitive values like challenges,
    signatures, or user handles.
    """

    def __init__(self, message: str, field: Optional[str] = None):
        self.field = field
        if field:
            super().__init__(f"{message} (at {field})")
        else:
            super().__init__(message)


class InvalidAuthenticatorDataStructure(WebAuthnException):
    pass


class SignatureVerificationException(WebAuthnException):
    pass


class UnsupportedAlgorithm(WebAuthnException):
    pass


class UnsupportedPublicKey(WebAuthnException):
    pass


class UnsupportedEC2Curve(WebAuthnException):
    pass


class InvalidTPMPubAreaStructure(WebAuthnException):
    pass


class InvalidTPMCertInfoStructure(WebAuthnException):
    pass


class InvalidCertificateChain(WebAuthnException):
    pass


class InvalidBackupFlags(WebAuthnException):
    pass


class InvalidCBORData(WebAuthnException):
    pass


class InvalidAttestationObjectStructure(WebAuthnException):
    pass
