import re
import ipaddress
from urllib.parse import urlparse

from evidence.models import IOCCollection


# Regex patterns for IOC extraction
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def extract_iocs(text: str) -> IOCCollection:
    """
    Extract Indicators of Compromise (IOCs) from text.

    Extracts:
    - URLs
    - Domains
    - IPv4 addresses
    - Email addresses
    """

    if not text:
        return IOCCollection()

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
    # 3. Extract IPv4 addresses
    # -----------------------------

    candidate_ips = set(IP_PATTERN.findall(text))
    valid_ips = set()

    for candidate in candidate_ips:
        try:
            ip = ipaddress.ip_address(candidate)

            if ip.version == 4:
                valid_ips.add(str(ip))

        except ValueError:
            # Ignore invalid addresses such as 999.999.999.999
            pass

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