# Well-known, high-traffic infrastructure. Sharing these says almost nothing
# about whether two cases are connected, so correlation ignores them.
# This is a starter list. Extend it as you see false links in testing.

ALLOWED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "office.com",
    "live.com", "apple.com", "amazon.com", "cloudflare.com", "github.com",
    "linkedin.com", "facebook.com", "yahoo.com",
}

ALLOWED_ASNS = {
    "AS13335",  # Cloudflare
    "AS15169",  # Google
    "AS8075",   # Microsoft
    "AS16509",  # Amazon
    "AS14618",  # Amazon
    "AS32934",  # Facebook / Meta
    "AS714",    # Apple
}


def is_allowlisted_domain(domain: str) -> bool:
    """True for the domain itself or any subdomain, e.g. mail.google.com."""
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in ALLOWED_DOMAINS)


def is_allowlisted_asn(asn: str) -> bool:
    return asn in ALLOWED_ASNS