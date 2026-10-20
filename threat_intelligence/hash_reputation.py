import os
import re

import requests

from threat_intelligence.cache import cached

API_URL = "https://mb-api.abuse.ch/api/v1/"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@cached(ttl_seconds=3600)
def check_hash_reputation(sha256: str) -> dict:
    """Ask MalwareBazaar (abuse.ch) whether a file hash is a known malware sample.

    status 'ok' + found False  -> hash is not in the database (this is NOT proof it is safe)
    status 'ok' + found True   -> hash is a catalogued malware sample
    """
    result = {"sha256": sha256, "status": "ok", "found": False,
              "signature": None, "file_type": None, "tags": []}

    if not SHA256_RE.match(sha256):
        result["status"] = "invalid_hash"
        return result

    key = os.environ.get("ABUSE_CH_KEY")
    if not key:
        result["status"] = "no_api_key"        # offline mode: skip quietly
        return result

    try:
        response = requests.post(
            API_URL,
            headers={"Auth-Key": key},
            data={"query": "get_info", "hash": sha256},
            timeout=10,
        )
        response.raise_for_status()
        body = response.json()
    except (requests.RequestException, ValueError):
        result["status"] = "lookup_failed"
        return result

    query_status = body.get("query_status")
    if query_status == "ok" and body.get("data"):
        sample = body["data"][0]
        result["found"] = True
        result["signature"] = sample.get("signature")
        result["file_type"] = sample.get("file_type")
        result["tags"] = sample.get("tags") or []
    elif query_status != "hash_not_found":
        result["status"] = "lookup_failed"     # unexpected answer, so don't cache it
    return result
