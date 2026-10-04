from email.utils import parseaddr
from typing import List


def extract_domain(address: str):
    """
    Extract the domain portion from an email address.
    """

    if not address:
        return None

    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


def analyze_headers(metadata) -> List[dict]:
    """
    Analyze important email-header relationships and return
    structured forensic observations.
    """

    findings = []

    sender_domain = extract_domain(metadata.sender)
    reply_to_domain = extract_domain(metadata.reply_to)
    return_path_domain = extract_domain(metadata.return_path)

    # From vs Reply-To
    if sender_domain and reply_to_domain:
        if sender_domain != reply_to_domain:
            findings.append({
                "signal_id": "HDR-001",
                "category": "header",
                "severity": "medium",
                "description": "From and Reply-To domains do not match",
                "evidence": {
                    "from_domain": sender_domain,
                    "reply_to_domain": reply_to_domain
                }
            })

    # From vs Return-Path
    if sender_domain and return_path_domain:
        if sender_domain != return_path_domain:
            findings.append({
                "signal_id": "HDR-002",
                "category": "header",
                "severity": "medium",
                "description": "From and Return-Path domains do not match",
                "evidence": {
                    "from_domain": sender_domain,
                    "return_path_domain": return_path_domain
                }
            })

    return findings