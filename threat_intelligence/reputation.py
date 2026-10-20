import os
import ipaddress
import requests

from threat_intelligence.cache import cached

API_URL = "https://api.abuseipdb.com/api/v2/check"


@cached(ttl_seconds=3600)
def check_ip_reputation(ip: str) -> dict:
    """Ask AbuseIPDB how malicious an IP looks (score 0-100)."""
    result = {"ip": ip, "status": "ok", "abuse_score": 0, "total_reports": 0}

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        result["status"] = "invalid_ip"
        return result
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        result["status"] = "private_or_reserved"
        return result

    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        result["status"] = "no_api_key"
        return result

    try:
        response = requests.get(
            API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()["data"]
        result["abuse_score"] = data.get("abuseConfidenceScore", 0)
        result["total_reports"] = data.get("totalReports", 0)
    except requests.RequestException:
        result["status"] = "lookup_failed"
    return result
