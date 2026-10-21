import re
import ipaddress
from urllib.parse import urlparse

from evidence.models import IOCCollection


# Regex patterns for IOC extraction.
# Quantifiers are bounded so hostile input cannot trigger quadratic
# backtracking (e.g. megabytes of "a.a.a.a...").
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b'
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

# Candidate IPv6 tokens; validated afterwards with ipaddress
IPV6_PATTERN = re.compile(
    r'(?<![0-9A-Fa-f:.])[0-9A-Fa-f:]{3,45}(?![0-9A-Fa-f:.])'
)

# Addresses that are not publicly routable. Documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are kept on
# purpose so demo data and tests still produce indicators.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(network) for network in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]

_DEFANG_REPLACEMENTS = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.IGNORECASE), "."),
    (re.compile(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    """
    Undo common 'defanging' used when sharing indicators safely, e.g.
    hxxps://evil[.]example[.]com  ->  https://evil.example.com
    """
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text


def is_internal_ip(value: str) -> bool:
    """True for loopback, private, link-local, multicast and reserved addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return any(ip in network
               for network in _INTERNAL_NETWORKS
               if network.version == ip.version)


def extract_iocs(text: str) -> IOCCollection:
    """
    Extract Indicators of Compromise (IOCs) from text.

    Extracts:
    - URLs
    - Domains
    - IPv4 and IPv6 addresses (internal addresses are filtered out)
    - Email addresses

    Defanged indicators (hxxp://, [.], [@]) are recognized and returned in
    their normal form.
    """

    if not text:
        return IOCCollection()

    text = refang(text)

    # -----------------------------
    # 1. Extract URLs
    # -----------------------------

    urls = set(URL_PATTERN.findall(text))

    # Remove common trailing punctuation
    cleaned_urls = set()

    for url in urls:
        cleaned_url = url.rstrip(".,);]}>")
        cleaned_urls.add(cleaned_url)

    urls = cleaned_urls

    # -----------------------------
    # 2. Extract email addresses
    # -----------------------------

    emails = set(EMAIL_PATTERN.findall(text))

    # -----------------------------
    # 3. Extract IPv4 / IPv6 addresses
    # -----------------------------

    valid_ips = set()

    for candidate in set(IP_PATTERN.findall(text)):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            # Ignore invalid addresses such as 999.999.999.999
            continue

        if ip.version == 4 and not is_internal_ip(str(ip)):
            valid_ips.add(str(ip))

    # "IPv6:2001:db8::1" (Received-header style) -> plain address
    ipv6_text = re.sub(r"(?i)\bipv6:", " ", text)

    for candidate in set(IPV6_PATTERN.findall(ipv6_text)):
        if ":" not in candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            # Times (12:30:45), MAC addresses and similar are not IPv6
            continue

        if ip.version == 6 and not is_internal_ip(str(ip)):
            valid_ips.add(str(ip))

    # -----------------------------
    # 4. Extract domains
    # -----------------------------

    domains = set()

    # Domains appearing inside URLs
    for url in urls:
        try:
            parsed = urlparse(url)

            if parsed.hostname:
                domains.add(parsed.hostname.lower())

        except ValueError:
            pass

    # Domains appearing in email addresses
    for email_address in emails:
        try:
            domain = email_address.split("@", 1)[1]
            domains.add(domain.lower())

        except IndexError:
            pass

    # -----------------------------
    # 5. Return structured IOC data
    # -----------------------------

    return IOCCollection(
        urls=sorted(urls),
        domains=sorted(domains),
        ips=sorted(valid_ips),
        emails=sorted(emails)
    )
