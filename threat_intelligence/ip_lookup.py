import ipaddress
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HTTPLookupError, ASNRegistryError
from functools import lru_cache

@lru_cache(maxsize=1024)
def lookup_ip(ip: str) -> dict:
    """Find ASN, organization, country and network for an IP using RDAP."""
    result = {
        "ip": ip,
        "status": "ok",
        "asn": None,
        "asn_description": None,
        "country": None,
        "network": None,
        "org": None,
    }

    # Step 1: check it's a valid IP at all
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        result["status"] = "invalid_ip"
        return result

    # Step 2: private IPs (like 192.168.x.x) can't be looked up publicly
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        result["status"] = "private_or_reserved"
        return result

    # Step 3: ask RDAP
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        result["asn"] = f"AS{data.get('asn')}" if data.get("asn") else None
        result["asn_description"] = data.get("asn_description")
        result["country"] = data.get("asn_country_code")
        network = data.get("network") or {}
        result["network"] = network.get("cidr")
        result["org"] = network.get("name")
    except (IPDefinedError, HTTPLookupError, ASNRegistryError):
        result["status"] = "lookup_failed"
    except Exception:
        result["status"] = "error"

    return result