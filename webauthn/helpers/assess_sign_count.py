from dataclasses import dataclass, field
from typing import List

from .structs import CredentialDeviceType, SignCountTransition


@dataclass
class SignCountAssessment:
    """Verified evidence about how a credential's sign count changed, and any risk it implies

    Attributes:
        `previous_sign_count`: The count the RP had stored for the credential
        `new_sign_count`: The count the authenticator reported in this response
        `credential_device_type`: Whether the credential is single- or multi-device
        `credential_backed_up`: Whether the credential is currently backed up
        `transition`: The classification of the counter change
        `is_risk`: Whether the transition warrants RP scrutiny (e.g. step-up auth)
        `reasons`: Human-readable explanations backing `is_risk`
    """

    previous_sign_count: int
    new_sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool
    transition: SignCountTransition
    is_risk: bool
    reasons: List[str] = field(default_factory=list)


def assess_sign_count(
    *,
    previous_sign_count: int,
    new_sign_count: int,
    credential_device_type: CredentialDeviceType,
    credential_backed_up: bool,
) -> SignCountAssessment:
    """Classify a sign count transition and decide whether it represents a risk

    A backup-eligible (multi-device) credential is not exempt from counter risk, and a
    normally-incrementing multi-device credential is not treated as cloned. Only a
    positive stored count that the new count fails to exceed is flagged, since synced
    passkeys may legitimately report zero or lag behind.
    """
    transition: SignCountTransition
    reasons: List[str] = []

    if previous_sign_count == 0 and new_sign_count == 0:
        transition = SignCountTransition.ZERO_TO_ZERO
        reasons.append(
            "Authenticator reported a sign count of zero, so counter-based clone"
            " detection is unavailable for this credential"
        )
    elif previous_sign_count == 0 and new_sign_count > 0:
        transition = SignCountTransition.COUNTING_STARTED
        reasons.append("Authenticator began reporting a non-zero sign count")
    elif new_sign_count > previous_sign_count:
        transition = SignCountTransition.NORMAL_INCREMENT
        reasons.append("Sign count increased as expected")
    else:
        transition = SignCountTransition.NOT_INCREMENTED
        reasons.append(
            f"Sign count of {new_sign_count} did not exceed the stored count of"
            f" {previous_sign_count}; this may indicate a cloned credential or a"
            " replayed response"
        )

    is_risk = transition == SignCountTransition.NOT_INCREMENTED

    return SignCountAssessment(
        previous_sign_count=previous_sign_count,
        new_sign_count=new_sign_count,
        credential_device_type=credential_device_type,
        credential_backed_up=credential_backed_up,
        transition=transition,
        is_risk=is_risk,
        reasons=reasons,
    )
