from typing import List


def generate_authentication_signals(authentication) -> List[dict]:
    """
    Convert authentication results into structured security signals.
    """

    signals = []

    if authentication.spf == "fail":
        signals.append({
            "signal_id": "AUTH-001",
            "category": "authentication",
            "severity": "medium",
            "description": "SPF authentication failed"
        })

    elif authentication.spf == "softfail":
        signals.append({
            "signal_id": "AUTH-002",
            "category": "authentication",
            "severity": "low",
            "description": "SPF authentication returned softfail"
        })

    if authentication.dkim == "fail":
        signals.append({
            "signal_id": "AUTH-003",
            "category": "authentication",
            "severity": "medium",
            "description": "DKIM authentication failed"
        })

    if authentication.dmarc == "fail":
        signals.append({
            "signal_id": "AUTH-004",
            "category": "authentication",
            "severity": "high",
            "description": "DMARC authentication failed"
        })

    return signals