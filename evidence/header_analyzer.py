import re
from email.utils import parseaddr
from typing import List, Optional

MAX_DISPLAY_NAME_CHARS = 300

_ADDRESS_IN_TEXT = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}"
)

_COMMON_TLDS = (
    "com|net|org|info|biz|io|co|in|us|uk|de|ru|cn|xyz|top|gov|edu"
)
_DOMAIN_IN_TEXT = re.compile(
    rf"\b(?:[a-z0-9-]{{1,63}}\.){{1,5}}(?:{_COMMON_TLDS})\b", re.IGNORECASE
)

_MESSAGE_ID_DOMAIN = re.compile(r"@([^>\s]+)")

# Small, deliberately conservative brand list (brand -> legitimate domains).
# Heuristic only: legitimate third-party senders can still trigger HDR-004.
BRAND_DOMAINS = {
    "paypal": ("paypal.com", "paypal.me"),
    "microsoft": ("microsoft.com", "office.com", "office365.com",
                  "outlook.com", "live.com", "microsoftonline.com",
                  "windows.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "facebookmail.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com", "facebookmail.com"),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "paytm": ("paytm.com",),
    "flipkart": ("flipkart.com",),
    "irctc": ("irctc.co.in", "irctc.com"),
    "hdfc": ("hdfcbank.com", "hdfcbank.net", "hdfc.com"),
    "icici": ("icicibank.com", "icici.com"),
    "sbi": ("sbi.co.in", "onlinesbi.com", "sbi.com"),
}


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


def _related(first: str, second: str) -> bool:
    """Same domain, or one is a subdomain of the other."""
    return (first == second
            or first.endswith("." + second)
            or second.endswith("." + first))


def _is_or_under(domain: str, legitimate: str) -> bool:
    return domain == legitimate or domain.endswith("." + legitimate)


def _display_name_findings(sender, sender_domain) -> List[dict]:
    """HDR-003 (display name shows another address) / HDR-004 (brand)."""
    if not sender or not sender_domain:
        return []

    name, _ = parseaddr(str(sender))
    name = (name or "")[:MAX_DISPLAY_NAME_CHARS]
    if not name:
        return []

    findings = []

    # HDR-003: the display name itself looks like an address or domain
    spoofed = None
    kind = None

    address_match = _ADDRESS_IN_TEXT.search(name)
    if address_match:
        shown_domain = address_match.group(0).rsplit("@", 1)[1].lower()
        if not _related(shown_domain, sender_domain):
            spoofed, kind = address_match.group(0).lower(), "email address"
    else:
        domain_match = _DOMAIN_IN_TEXT.search(name)
        if domain_match:
            shown_domain = domain_match.group(0).lower()
            if not _related(shown_domain, sender_domain):
                spoofed, kind = shown_domain, "domain"

    if spoofed:
        findings.append({
            "signal_id": "HDR-003",
            "category": "header",
            "severity": "high" if kind == "email address" else "medium",
            "description": "Display name shows a different "
                           f"{kind} than the real sender",
            "evidence": {
                "display_name": name,
                "shown": spoofed,
                "from_domain": sender_domain,
            },
        })
        return findings   # HDR-004 would only repeat the same fact

    # HDR-004: the display name claims a well-known brand
    lowered = name.lower()
    for brand, legitimate_domains in BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", lowered):
            if not any(_is_or_under(sender_domain, legit)
                       for legit in legitimate_domains):
                findings.append({
                    "signal_id": "HDR-004",
                    "category": "header",
                    "severity": "medium",
                    "description": "Display name claims a known brand but "
                                   "the sender domain is unrelated to it",
                    "evidence": {
                        "display_name": name,
                        "brand": brand,
                        "from_domain": sender_domain,
                    },
                })
            break

    return findings


def _message_id_domain(message_id) -> Optional[str]:
    if not message_id:
        return None
    match = _MESSAGE_ID_DOMAIN.search(str(message_id)[:998])
    if not match:
        return None
    return match.group(1).strip(">").lower() or None


def analyze_headers(metadata) -> List[dict]:
    """
    Analyze important email-header relationships and return
    structured forensic observations.

    Signals:
      HDR-001  From vs Reply-To domain mismatch
      HDR-002  From vs Return-Path domain mismatch
      HDR-003  Display name shows a different address/domain than the sender
      HDR-004  Display name claims a known brand the sender domain doesn't own
      HDR-005  Message-ID domain unrelated to the From domain
      HDR-006  Message-ID header missing
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

    # Display-name spoofing / brand impersonation
    try:
        findings.extend(
            _display_name_findings(metadata.sender, sender_domain)
        )
    except Exception:
        pass

    # Message-ID checks
    try:
        message_id_domain = _message_id_domain(metadata.message_id)

        if not metadata.message_id:
            findings.append({
                "signal_id": "HDR-006",
                "category": "header",
                "severity": "low",
                "description": "Message-ID header is missing",
                "evidence": {}
            })
        elif (sender_domain and message_id_domain
              and not _related(message_id_domain, sender_domain)):
            findings.append({
                "signal_id": "HDR-005",
                "category": "header",
                "severity": "low",
                "description": "Message-ID domain is unrelated to the "
                               "From domain",
                "evidence": {
                    "from_domain": sender_domain,
                    "message_id_domain": message_id_domain
                }
            })
    except Exception:
        pass

    return findings
