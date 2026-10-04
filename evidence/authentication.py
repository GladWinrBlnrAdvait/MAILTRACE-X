import re

from evidence.models import AuthenticationEvidence


VALID_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror"
}


def _extract_result(header_value: str, mechanism: str) -> str:
    """
    Extract an authentication mechanism result from
    Authentication-Results.
    """

    pattern = rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z]+)"

    match = re.search(
        pattern,
        header_value,
        flags=re.IGNORECASE
    )

    if not match:
        return "unknown"

    result = match.group(1).lower()

    if result in VALID_RESULTS:
        return result

    return "unknown"


def analyze_authentication(message) -> AuthenticationEvidence:
    """
    Parse authentication evidence contained in email headers.

    NOTE:
    This reads reported Authentication-Results.
    It does NOT independently perform SPF, DKIM or DMARC
    cryptographic/DNS validation.
    """

    auth_headers = message.get_all("Authentication-Results", [])

    combined = " ".join(str(header) for header in auth_headers)

    spf = _extract_result(combined, "spf")
    dkim = _extract_result(combined, "dkim")
    dmarc = _extract_result(combined, "dmarc")

    # Received-SPF can provide SPF evidence if SPF was not found
    # in Authentication-Results.
    if spf == "unknown":
        received_spf = message.get("Received-SPF")

        if received_spf:
            first_word = str(received_spf).strip().split()[0].lower()

            if first_word in VALID_RESULTS:
                spf = first_word

    return AuthenticationEvidence(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc
    )