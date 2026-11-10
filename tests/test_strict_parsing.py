import base64
import json
from unittest import TestCase

from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import (
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_client_data_json,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
    StrictValidationError,
)
from webauthn.helpers.strict import strict_json_loads
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


# A known-good authentication response (EC2 key) from test_verify_authentication_response
AUTH_CREDENTIAL = {
    "id": "EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q",
    "rawId": "EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAATg",
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4aTMwR1BHQUZZUnhWRHBZMXNNMTBEYUx6VlFHNjZudi1fN1JVYXpIMHZJMll2RzhMWWdERW52TjVmWlpOVnV2RUR1TWk5dGUzVkxxYjQyTjBma0xHQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
        "signature": "MEUCIGisVZOBapCWbnJJvjelIzwpixxIwkjCCb5aCHafQu68AiEA88v-2pJNNApPFwAKFiNuf82-2hBxYW5kGwVweeoxCwo",
    },
    "type": "public-key",
    "clientExtensionResults": {},
}
AUTH_CHALLENGE = base64url_to_bytes(
    "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA"
)
AUTH_PUBLIC_KEY = base64url_to_bytes(
    "pQECAyYgASFYIIeDTe-gN8A-zQclHoRnGFWN8ehM1b7yAsa8I8KIvmplIlgg4nFGT5px8o6gpPZZhO01wdy9crDSA_Ngtkx0vGpvPHI"
)
AUTH_KW = dict(
    expected_challenge=AUTH_CHALLENGE,
    expected_rp_id="localhost",
    expected_origin="http://localhost:5000",
    credential_public_key=AUTH_PUBLIC_KEY,
    credential_current_sign_count=77,
)

# A known-good "none" attestation registration response
REG_CREDENTIAL = {
    "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
    "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "transports": ["nfc", "usb"],
}
REG_CHALLENGE = base64url_to_bytes(
    "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
)
REG_KW = dict(
    expected_challenge=REG_CHALLENGE,
    expected_rp_id="localhost",
    expected_origin="http://localhost:5000",
)


class TestStrictJSONLoader(TestCase):
    def test_rejects_duplicate_top_level_key(self) -> None:
        with self.assertRaisesRegex(StrictValidationError, "Duplicate key") as ctx:
            strict_json_loads('{"origin":"a","origin":"b"}')
        self.assertEqual(ctx.exception.field, "origin")

    def test_rejects_duplicate_nested_key(self) -> None:
        with self.assertRaisesRegex(StrictValidationError, "Duplicate key") as ctx:
            strict_json_loads(
                '{"tokenBinding":{"status":"present","status":"supported"}}'
            )
        self.assertEqual(ctx.exception.field, "status")

    def test_rejects_duplicate_key_inside_unknown_extension(self) -> None:
        # Duplicate detection applies to the whole raw document, not just known fields.
        with self.assertRaisesRegex(StrictValidationError, "Duplicate key") as ctx:
            strict_json_loads(
                '{"id":"x","clientExtensionResults":{"appId":true,"appId":false}}'
            )
        self.assertEqual(ctx.exception.field, "appId")

    def test_empty_identifier_is_rejected(self) -> None:
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["id"] = ""
        credential["rawId"] = ""
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )
        self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
        self.assertEqual(ctx.exception.__cause__.field, "id")

    def test_retains_distinct_unknown_fields(self) -> None:
        parsed = strict_json_loads(
            '{"type":"webauthn.get","futureExt":{"a":1},"other":[1,2]}'
        )
        self.assertEqual(parsed["futureExt"], {"a": 1})
        self.assertEqual(parsed["other"], [1, 2])

    def test_rejects_non_object_documents(self) -> None:
        for non_object in ['[1, 2]', '"a string"', "42", "null"]:
            with self.subTest(non_object=non_object):
                with self.assertRaisesRegex(StrictValidationError, "not a JSON object"):
                    strict_json_loads(non_object)

    def test_dict_passthrough_cannot_detect_lost_duplicates(self) -> None:
        # A dict literal has already collapsed duplicates, so strict mode only runs structural
        # checks on it rather than pretending it can recover lost keys.
        collapsed = {"id": "first", **{"id": "second"}}
        self.assertEqual(strict_json_loads(collapsed), {"id": "second"})

    def test_invalid_json_raises_strict_validation_error(self) -> None:
        with self.assertRaises(StrictValidationError):
            strict_json_loads("{not valid json")

    def test_is_an_invalid_json_structure(self) -> None:
        # Backwards-compatible exception hierarchy.
        self.assertTrue(issubclass(StrictValidationError, InvalidJSONStructure))


class TestStrictClientDataJSON(TestCase):
    def _client_data(self, raw: bytes) -> object:
        return parse_client_data_json(raw, strict=True)

    def test_duplicate_origin_rejected_before_dict_is_built(self) -> None:
        raw = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"https://good.example",'
            b'"origin":"https://evil.example"}'
        )
        with self.assertRaisesRegex(StrictValidationError, "Duplicate key") as ctx:
            self._client_data(raw)
        self.assertEqual(ctx.exception.field, "origin")

    def test_string_cross_origin_is_rejected(self) -> None:
        raw = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
            b'"crossOrigin":"false"}'
        )
        with self.assertRaisesRegex(StrictValidationError, "Expected a boolean") as ctx:
            self._client_data(raw)
        self.assertEqual(ctx.exception.field, "crossOrigin")

    def test_numeric_cross_origin_is_rejected(self) -> None:
        for number in (b"0", b"1"):
            with self.subTest(number=number):
                raw = (
                    b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
                    b'"crossOrigin":' + number + b"}"
                )
                with self.assertRaisesRegex(StrictValidationError, "Expected a boolean"):
                    self._client_data(raw)

    def test_real_boolean_cross_origin_accepted(self) -> None:
        raw = b'{"type":"webauthn.get","challenge":"AAAA","origin":"o","crossOrigin":true}'
        parsed = self._client_data(raw)
        self.assertIs(parsed.cross_origin, True)

    def test_challenge_must_be_base64url_string(self) -> None:
        raw = b'{"type":"webauthn.get","challenge":123,"origin":"o"}'
        with self.assertRaisesRegex(StrictValidationError, "Expected str") as ctx:
            self._client_data(raw)
        self.assertEqual(ctx.exception.field, "challenge")

    def test_required_fields_are_reported_by_name(self) -> None:
        raw = b'{"type":"webauthn.get","origin":"o"}'
        with self.assertRaisesRegex(StrictValidationError, "Missing required field") as ctx:
            self._client_data(raw)
        self.assertEqual(ctx.exception.field, "challenge")

    def test_unknown_fields_are_ignored_not_used_as_overrides(self) -> None:
        raw = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
            b'"crossOrigin":false,"futureExtension":{"k":"v"}}'
        )
        parsed = self._client_data(raw)
        self.assertEqual(parsed.origin, "o")
        self.assertIs(parsed.cross_origin, False)

    def test_token_binding_strict_validation(self) -> None:
        good = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
            b'"tokenBinding":{"status":"present","id":"binding-id"}}'
        )
        parsed = self._client_data(good)
        self.assertEqual(parsed.token_binding.id, "binding-id")

        bad_status = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
            b'"tokenBinding":{"status":"nope"}}'
        )
        with self.assertRaisesRegex(StrictValidationError, "tokenBinding.status"):
            self._client_data(bad_status)

        not_object = (
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o",'
            b'"tokenBinding":"present"}'
        )
        with self.assertRaisesRegex(StrictValidationError, "tokenBinding"):
            self._client_data(not_object)

    def test_lenient_default_unchanged(self) -> None:
        # The default (non-strict) path keeps its historical coercion / last-wins behavior.
        coerced = parse_client_data_json(
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"o","crossOrigin":"false"}'
        )
        self.assertIs(coerced.cross_origin, True)

        last_wins = parse_client_data_json(
            b'{"type":"webauthn.get","challenge":"AAAA","origin":"a","origin":"b"}'
        )
        self.assertEqual(last_wins.origin, "b")


class TestStrictAuthenticationCredential(TestCase):
    def test_happy_path_string_dict_object_equivalent(self) -> None:
        for credential in (
            json.dumps(AUTH_CREDENTIAL),
            AUTH_CREDENTIAL,
            parse_authentication_credential_json(AUTH_CREDENTIAL, strict=True),
        ):
            with self.subTest(kind=type(credential).__name__):
                verification = verify_authentication_response(
                    credential=credential, strict=True, **AUTH_KW
                )
                self.assertEqual(verification.new_sign_count, 78)

    def test_original_client_data_json_bytes_are_preserved(self) -> None:
        original = base64url_to_bytes(AUTH_CREDENTIAL["response"]["clientDataJSON"])
        parsed = parse_authentication_credential_json(
            json.dumps(AUTH_CREDENTIAL), strict=True
        )
        # Strict parsing must decode but never re-encode clientDataJSON.
        self.assertEqual(parsed.response.client_data_json, original)

    def test_duplicate_origin_rejected_through_full_verify(self) -> None:
        # Build a clientDataJSON with a duplicated origin; the bytes stay raw inside the wrapper.
        good_challenge = "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA"
        raw = (
            b'{"type":"webauthn.get","challenge":"' + good_challenge.encode()
            + b'","origin":"http://localhost:5000","origin":"http://evil.example"}'
        )
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["response"]["clientDataJSON"] = _b64url(raw)

        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=json.dumps(credential), strict=True, **AUTH_KW
            )
        self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
        self.assertEqual(ctx.exception.__cause__.field, "origin")

    def test_duplicate_wrapper_key_rejected_for_raw_json(self) -> None:
        raw = json.dumps(AUTH_CREDENTIAL)
        duplicated = raw.replace(
            '"type": "public-key"',
            '"type": "public-key", "type": "public-key"',
            1,
        )
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(credential=duplicated, strict=True, **AUTH_KW)
        self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
        self.assertEqual(ctx.exception.__cause__.field, "type")

    def test_string_cross_origin_rejected_through_full_verify(self) -> None:
        good_challenge = "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA"
        raw = (
            b'{"type":"webauthn.get","challenge":"' + good_challenge.encode()
            + b'","origin":"http://localhost:5000","crossOrigin":"false"}'
        )
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["response"]["clientDataJSON"] = _b64url(raw)

        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )
        self.assertEqual(ctx.exception.__cause__.field, "crossOrigin")

    def test_contradictory_id_and_raw_id_rejected(self) -> None:
        for shape in ("dict", "string"):
            with self.subTest(shape=shape):
                credential = json.loads(json.dumps(AUTH_CREDENTIAL))
                credential["rawId"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                payload = (
                    json.dumps(credential) if shape == "string" else credential
                )
                with self.assertRaises(InvalidAuthenticationResponse) as ctx:
                    verify_authentication_response(
                        credential=payload, strict=True, **AUTH_KW
                    )
                self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
                self.assertEqual(ctx.exception.__cause__.field, "rawId")

    def test_illegal_encoding_rejected_for_each_binary_field(self) -> None:
        fields = {
            "rawId": "has space",
            "response.authenticatorData": "bad!!!",
            "response.clientDataJSON": "not*base64*",
            "response.signature": "Uf6",  # valid alphabet; force bad length via mod 4 == 1 below
        }
        # "Uf6" is length 3 which is valid; use a length-1 (mod 4 == 1) token instead.
        fields["response.signature"] = "A"
        for field, bad_value in fields.items():
            with self.subTest(field=field):
                credential = json.loads(json.dumps(AUTH_CREDENTIAL))
                target = credential
                for part in field.split(".")[:-1]:
                    target = target[part]
                target[field.split(".")[-1]] = bad_value

                with self.assertRaises(InvalidAuthenticationResponse) as ctx:
                    verify_authentication_response(
                        credential=credential, strict=True, **AUTH_KW
                    )
                self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
                self.assertEqual(ctx.exception.__cause__.field, field)

    def test_boolean_and_type_confusion_rejected(self) -> None:
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["id"] = 12345  # numeric instead of string
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )
        self.assertEqual(ctx.exception.__cause__.field, "id")

    def test_user_handle_must_be_base64url_string(self) -> None:
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["response"]["userHandle"] = 99
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )
        self.assertEqual(ctx.exception.__cause__.field, "response.userHandle")

    def test_unknown_extension_field_does_not_override_known_fields(self) -> None:
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["futureUnknownField"] = {"nested": [1, 2, 3]}
        credential["clientExtensionResults"] = {"custom": True}
        verification = verify_authentication_response(
            credential=credential, strict=True, **AUTH_KW
        )
        self.assertEqual(verification.new_sign_count, 78)

    def test_constructed_object_gets_equivalent_checks(self) -> None:
        good = parse_authentication_credential_json(AUTH_CREDENTIAL, strict=True)
        verification = verify_authentication_response(
            credential=good, strict=True, **AUTH_KW
        )
        self.assertEqual(verification.new_sign_count, 78)

        contradictory = AuthenticationCredential(
            id=good.id,
            raw_id=b"\x00\x01\x02\x03",
            response=good.response,
        )
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=contradictory, strict=True, **AUTH_KW
            )
        self.assertEqual(ctx.exception.__cause__.field, "rawId")

        wrong_type = AuthenticationCredential(
            id=123,  # type: ignore[arg-type]
            raw_id=good.raw_id,
            response=good.response,
        )
        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=wrong_type, strict=True, **AUTH_KW
            )
        self.assertEqual(ctx.exception.__cause__.field, "id")

    def test_error_messages_do_not_leak_sensitive_values(self) -> None:
        signature = AUTH_CREDENTIAL["response"]["signature"]
        challenge_b64 = (
            "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA"
        )
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["response"]["signature"] = "not base64!!"

        with self.assertRaises(InvalidAuthenticationResponse) as ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )

        rendered = f"{ctx.exception} {ctx.exception.__cause__}"
        self.assertNotIn(signature, rendered)
        self.assertNotIn(challenge_b64, rendered)

        # A userHandle failure likewise must not echo the handle value.
        credential = parse_authentication_credential_json(AUTH_CREDENTIAL, strict=True)
        leaking = AuthenticationCredential(
            id=credential.id,
            raw_id=credential.raw_id,
            response=AuthenticatorAssertionResponse(
                client_data_json=credential.response.client_data_json,
                authenticator_data=credential.response.authenticator_data,
                signature=credential.response.signature,
                user_handle="not-bytes",  # type: ignore[arg-type]
            ),
        )
        with self.assertRaises(InvalidAuthenticationResponse) as ctx2:
            verify_authentication_response(
                credential=leaking, strict=True, **AUTH_KW
            )
        self.assertNotIn("not-bytes", str(ctx2.exception.__cause__))

    def test_no_bypass_when_strict_disabled_vs_enabled(self) -> None:
        # The same contradictory payload verifies the parsing stage differently: strict mode stops
        # it at structural validation, proving there is no alternate entry that skips the checks.
        credential = json.loads(json.dumps(AUTH_CREDENTIAL))
        credential["rawId"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        with self.assertRaises(InvalidAuthenticationResponse) as strict_ctx:
            verify_authentication_response(
                credential=credential, strict=True, **AUTH_KW
            )
        self.assertIsInstance(strict_ctx.exception.__cause__, StrictValidationError)

        # Non-strict mode performs the same id/rawId equivalence check further down, just without
        # the strict cause type.
        with self.assertRaises(InvalidAuthenticationResponse) as lenient_ctx:
            verify_authentication_response(
                credential=credential, strict=False, **AUTH_KW
            )
        self.assertNotIsInstance(lenient_ctx.exception.__cause__, StrictValidationError)


class TestStrictRegistrationCredential(TestCase):
    def test_happy_path_all_three_shapes(self) -> None:
        for credential in (
            json.dumps(REG_CREDENTIAL),
            REG_CREDENTIAL,
            parse_registration_credential_json(REG_CREDENTIAL, strict=True),
        ):
            with self.subTest(kind=type(credential).__name__):
                verification = verify_registration_response(
                    credential=credential, strict=True, **REG_KW
                )
                self.assertEqual(verification.sign_count, 23)

    def test_duplicate_challenge_rejected_through_full_verify(self) -> None:
        # Construct raw clientDataJSON with a duplicated challenge by hand.
        challenge_b64 = (
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        raw = (
            b'{"type":"webauthn.create","challenge":"' + challenge_b64.encode()
            + b'","challenge":"OTHER","origin":"http://localhost:5000"}'
        )
        credential = json.loads(json.dumps(REG_CREDENTIAL))
        credential["response"]["clientDataJSON"] = _b64url(raw)

        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=json.dumps(credential), strict=True, **REG_KW
            )
        self.assertIsInstance(ctx.exception.__cause__, StrictValidationError)
        self.assertEqual(ctx.exception.__cause__.field, "challenge")

    def test_bad_attestation_encoding_rejected(self) -> None:
        credential = json.loads(json.dumps(REG_CREDENTIAL))
        credential["response"]["attestationObject"] = "bad encoding!!"
        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential, strict=True, **REG_KW
            )
        self.assertEqual(
            ctx.exception.__cause__.field, "response.attestationObject"
        )

    def test_bad_transport_entry_rejected(self) -> None:
        credential = json.loads(json.dumps(REG_CREDENTIAL))
        credential["response"]["transports"] = ["nfc", 7]
        with self.assertRaises(InvalidRegistrationResponse) as ctx:
            verify_registration_response(
                credential=credential, strict=True, **REG_KW
            )
        self.assertEqual(
            ctx.exception.__cause__.field, "response.transports[1]"
        )

    def test_unknown_extensions_are_retained_and_tolerated(self) -> None:
        credential = json.loads(json.dumps(REG_CREDENTIAL))
        credential["clientExtensionResults"] = {"appId": True, "custom": {"x": 1}}
        verification = verify_registration_response(
            credential=credential, strict=True, **REG_KW
        )
        self.assertEqual(verification.sign_count, 23)
