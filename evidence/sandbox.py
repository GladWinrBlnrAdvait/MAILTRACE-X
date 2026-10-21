"""
Optional hash-reputation and sandbox-behaviour enrichment (VirusTotal).

What it does
------------
For each attachment, looks up the file's SHA-256 on VirusTotal:
  1. the file report (antivirus engine verdicts), and
  2. if engines flagged it, the behaviour summary (what VirusTotal's own
     sandboxes observed when they ran the file).

Only the HASH is sent. Attachments are never uploaded and nothing is run
locally. A hash VirusTotal has never seen simply returns "not_found".

Switched OFF by default. To enable, set BOTH environment variables:
    MAILTRACE_SANDBOX_PROVIDER=virustotal
    VT_API_KEY=<your key>

Signals
-------
    SBX-001  Antivirus engines flag the attachment (severity by engine count)
    SBX-002  At least half of the sandboxes returned a non-clean verdict
    SBX-003  Sandbox observed MITRE ATT&CK techniques (informational)

Design notes (state in the paper)
---------------------------------
  * Sandbox reports are huge and noisy even for harmless files, so raw counts
    (files opened, registry keys...) are never used. Only curated fields.
  * Sandboxes disagree with each other, so SBX-002 is capped at "medium".
  * Everything copied out of a report is untrusted text: it is type-checked,
    stripped of control characters and truncated before being stored.
  * Sandbox network traffic is deliberately NOT turned into IOCs; it is mostly
    the sandbox VM's own traffic and would create false correlations.
  * Free-tier limit is 4 requests/minute. A small in-process limiter refuses
    to exceed it (status "rate_limited") instead of blocking the API.
  * Failures (no key, timeout, 403, 429, bad JSON) never raise: the pipeline
    carries on without sandbox data.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Dict, List, Optional, Tuple

API_BASE = "https://www.virustotal.com/api/v3"
PROVIDER_ENV = "MAILTRACE_SANDBOX_PROVIDER"
KEY_ENV = "VT_API_KEY"

REQUEST_TIMEOUT = 8                    # seconds per HTTP call
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
RATE_LIMIT_CALLS = 4                   # free tier: 4 requests / minute
RATE_LIMIT_WINDOW = 60.0
CACHE_TTL = 3600.0
MAX_LOOKUPS_PER_EMAIL = 3

# Heuristic thresholds on VirusTotal engine detections (tunable)
MALICIOUS_HIGH = 10
MALICIOUS_MEDIUM = 3

MAX_TECHNIQUES = 5
MAX_VERDICTS = 10
DESCRIPTION_LIMIT = 200

_SHA256 = re.compile(r"[0-9a-f]{64}")
_TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_lock = threading.Lock()
_recent_calls: deque = deque()
_cache: Dict[str, Tuple[float, dict]] = {}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def is_enabled() -> bool:
    provider = os.environ.get(PROVIDER_ENV, "").strip().lower()
    return provider == "virustotal" and bool(os.environ.get(KEY_ENV, "").strip())


def _reset_state() -> None:
    """Clear the cache and rate limiter (used by tests)."""
    with _lock:
        _recent_calls.clear()
        _cache.clear()


def _clean_text(value, limit: int) -> str:
    """Untrusted text -> single-line, control-free, length-limited string."""
    if not isinstance(value, str):
        return ""
    text = _CONTROL_CHARS.sub(" ", value)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _as_count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _dig(obj, *keys):
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _severity_rank(label) -> int:
    text = label.upper() if isinstance(label, str) else ""
    if "HIGH" in text:
        return 3
    if "MEDIUM" in text:
        return 2
    if "LOW" in text:
        return 1
    return 0


_RANK_NAMES = {3: "high", 2: "medium", 1: "low", 0: "unspecified"}


def _acquire_slot() -> bool:
    """Sliding-window limiter: True if a request may be made now."""
    now = time.monotonic()
    with _lock:
        while _recent_calls and now - _recent_calls[0] > RATE_LIMIT_WINDOW:
            _recent_calls.popleft()
        if len(_recent_calls) >= RATE_LIMIT_CALLS:
            return False
        _recent_calls.append(now)
        return True


def _cache_get(sha256: str) -> Optional[dict]:
    with _lock:
        entry = _cache.get(sha256)
        if entry and time.monotonic() - entry[0] < CACHE_TTL:
            return entry[1]
        _cache.pop(sha256, None)
    return None


def _cache_set(sha256: str, summary: dict) -> None:
    with _lock:
        _cache[sha256] = (time.monotonic(), summary)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _get_json(path: str, api_key: str,
              timeout: float = REQUEST_TIMEOUT) -> Tuple[int, Optional[dict]]:
    """
    GET {API_BASE}{path}. Returns (http_status, parsed_json_or_None).
    Status 0 means the request itself failed (timeout, DNS, bad JSON...).
    The API key is only ever sent as a header and is never logged.
    """
    request = urllib.request.Request(
        API_BASE + path,
        headers={
            "x-apikey": api_key,
            "accept": "application/json",
            "User-Agent": "MAILTRACE-X",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return 0, None
            return response.status, json.loads(body.decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        return error.code, None
    except Exception:
        return 0, None


# ---------------------------------------------------------------------------
# Parsing (pure functions: data in, data out)
# ---------------------------------------------------------------------------

def summarize_vt_report(report: Optional[dict],
                        behaviour: Optional[dict]) -> dict:
    """
    Reduce the (large) VirusTotal responses to a small, safe summary.
    Either argument may be None. Never raises on unexpected shapes.
    """
    summary = {
        "status": "not_found",
        "engines": {"malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0},
        "threat_label": None,
        "behaviour": {"available": False, "sandboxes_total": 0,
                      "sandboxes_non_clean": 0, "verdicts": []},
        "techniques": [],
    }

    attributes = _dig(report, "data", "attributes")
    if isinstance(attributes, dict):
        summary["status"] = "ok"
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        for key in summary["engines"]:
            summary["engines"][key] = _as_count(stats.get(key))
        label = _dig(attributes, "popular_threat_classification",
                     "suggested_threat_label")
        cleaned = _clean_text(label, 80)
        summary["threat_label"] = cleaned or None

    data = _dig(behaviour, "data")
    if isinstance(data, dict):
        summary["behaviour"]["available"] = True

        raw_verdicts = data.get("verdicts")
        verdicts = [
            _clean_text(v, 20).upper()
            for v in (raw_verdicts if isinstance(raw_verdicts, list) else [])
            if isinstance(v, str) and _clean_text(v, 20)
        ]
        summary["behaviour"]["sandboxes_total"] = len(verdicts)
        summary["behaviour"]["sandboxes_non_clean"] = sum(
            1 for v in verdicts if v != "CLEAN"
        )
        summary["behaviour"]["verdicts"] = verdicts[:MAX_VERDICTS]

        techniques: Dict[str, dict] = {}
        raw_techniques = data.get("mitre_attack_techniques")
        for item in (raw_techniques if isinstance(raw_techniques, list) else []):
            if not isinstance(item, dict):
                continue
            technique_id = item.get("id")
            if not isinstance(technique_id, str):
                continue
            technique_id = technique_id.strip()
            if not _TECHNIQUE_ID.fullmatch(technique_id):
                continue
            rank = _severity_rank(item.get("severity"))
            existing = techniques.get(technique_id)
            if existing is None or rank > existing["rank"]:
                techniques[technique_id] = {
                    "id": technique_id,
                    "rank": rank,
                    "description": _clean_text(
                        item.get("signature_description"), DESCRIPTION_LIMIT
                    ),
                }
        ordered = sorted(techniques.values(),
                         key=lambda t: (-t["rank"], t["id"]))[:MAX_TECHNIQUES]
        summary["techniques"] = [
            {"id": t["id"], "severity": _RANK_NAMES[t["rank"]],
             "description": t["description"]}
            for t in ordered
        ]

    return summary


def _signal(signal_id: str, severity: str, description: str,
            filename: str, sha256: str, **evidence) -> dict:
    return {
        "signal_id": signal_id,
        "category": "attachment",
        "severity": severity,
        "description": description,
        "evidence": {"filename": filename, "sha256": sha256, **evidence},
    }


def signals_from_summary(filename: str, sha256: str, summary: dict) -> List[dict]:
    """Turn a summary into SBX-xxx signals (empty if there is nothing to say)."""
    if not isinstance(summary, dict) or summary.get("status") != "ok":
        return []

    signals: List[dict] = []
    engines = summary.get("engines") or {}
    malicious = _as_count(engines.get("malicious"))

    if malicious >= 1:
        if malicious >= MALICIOUS_HIGH:
            severity = "high"
        elif malicious >= MALICIOUS_MEDIUM:
            severity = "medium"
        else:
            severity = "low"
        signals.append(_signal(
            "SBX-001", severity,
            "Antivirus engines flag this attachment as malicious",
            filename, sha256,
            malicious=malicious,
            suspicious=_as_count(engines.get("suspicious")),
            threat_label=summary.get("threat_label"),
        ))

    behaviour = summary.get("behaviour") or {}
    total = _as_count(behaviour.get("sandboxes_total"))
    non_clean = _as_count(behaviour.get("sandboxes_non_clean"))
    if total > 0 and non_clean * 2 >= total:
        signals.append(_signal(
            "SBX-002", "medium",
            "Sandbox analysis returned a non-clean verdict",
            filename, sha256,
            sandboxes_total=total, sandboxes_non_clean=non_clean,
            verdicts=behaviour.get("verdicts", []),
        ))

    techniques = summary.get("techniques") or []
    if techniques:
        signals.append(_signal(
            "SBX-003", "low",
            "Sandbox observed MITRE ATT&CK techniques (informational)",
            filename, sha256,
            techniques=[{"id": t.get("id"), "severity": t.get("severity")}
                        for t in techniques],
        ))

    return signals


# ---------------------------------------------------------------------------
# Lookup and enrichment
# ---------------------------------------------------------------------------

def lookup_hash(sha256: str) -> dict:
    """
    Look up one SHA-256. Always returns a dict with a "status":
      disabled | invalid_hash | rate_limited | unauthorized | unavailable
      | not_found | ok
    """
    if not is_enabled():
        return {"status": "disabled"}

    sha256 = (sha256 or "").strip().lower()
    if not _SHA256.fullmatch(sha256):
        return {"status": "invalid_hash"}

    cached = _cache_get(sha256)
    if cached is not None:
        return cached

    api_key = os.environ[KEY_ENV].strip()

    if not _acquire_slot():
        return {"status": "rate_limited"}
    code, report = _get_json(f"/files/{sha256}", api_key)

    if code == 404:
        result = summarize_vt_report(None, None)
        _cache_set(sha256, result)
        return result
    if code in (401, 403):
        return {"status": "unauthorized"}
    if code == 429:
        return {"status": "rate_limited"}
    if code != 200 or not isinstance(report, dict):
        return {"status": "unavailable"}

    behaviour = None
    engines = summarize_vt_report(report, None)["engines"]
    if engines["malicious"] + engines["suspicious"] >= 1 and _acquire_slot():
        behaviour_code, behaviour_data = _get_json(
            f"/files/{sha256}/behaviour_summary", api_key
        )
        if behaviour_code == 200 and isinstance(behaviour_data, dict):
            behaviour = behaviour_data

    result = summarize_vt_report(report, behaviour)
    _cache_set(sha256, result)
    return result


def enrich_attachments(attachments) -> None:
    """
    Add sandbox summaries and SBX signals to attachments, in place.
    Does nothing unless enabled. Never raises.
    """
    if not is_enabled():
        return

    looked_up = 0
    for attachment in attachments:
        if looked_up >= MAX_LOOKUPS_PER_EMAIL:
            break
        if not getattr(attachment, "sha256", None) or not attachment.size_bytes:
            continue
        looked_up += 1
        try:
            summary = lookup_hash(attachment.sha256)
            attachment.sandbox = summary
            attachment.signals.extend(signals_from_summary(
                attachment.filename, attachment.sha256, summary
            ))
        except Exception:
            attachment.sandbox = {"status": "unavailable"}
