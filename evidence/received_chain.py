"""
Received-header timeline.

Mail servers each prepend a Received header, so the LAST header in the
message is the OLDEST hop. This module reverses them into chronological
order and extracts, per hop: the sending host and IP, the receiving host,
the protocol and the timestamp (plus the delay since the previous hop).

Signals:
    HDR-007  Hop timestamps go backwards (clock skew or header tampering)

The origin IP is a best-effort guess: the first non-internal IP seen in the
chronological chain. Received headers added by the sender's own system can
be forged, so only hops added by servers you trust are reliable.
"""

import ipaddress
import re
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple

from evidence.ioc_extractor import is_internal_ip

MAX_HOPS = 100
MAX_FIELD_CHARS = 255
OUT_OF_ORDER_TOLERANCE_SECONDS = 300

_FROM = re.compile(r"^\s*from\s+(\S+)", re.IGNORECASE)
_BY_CLAUSE = re.compile(r"\bby\s", re.IGNORECASE)
_BY_HOST = re.compile(r"^\s*by\s+(\S+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{2,45})\]", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = _CONTROL_CHARS.sub(" ", value).strip().strip("<>;,")
    return cleaned[:MAX_FIELD_CHARS] or None


def _first_valid_ip(text: str) -> Optional[str]:
    for match in _BRACKET_IP.finditer(text):
        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            continue
    for match in _IPV4.finditer(text):
        try:
            return str(ipaddress.ip_address(match.group(0)))
        except ValueError:
            continue
    return None


def _parse_timestamp(text: str):
    try:
        return parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _parse_hop(header: str) -> Tuple[dict, Optional[object]]:
    text = " ".join(str(header)[:4000].split())

    body, separator, timestamp_text = text.rpartition(";")
    if not separator:
        body, timestamp_text = text, ""

    by_match = _BY_CLAUSE.search(body)
    from_part = body[:by_match.start()] if by_match else body
    by_part = body[by_match.start():] if by_match else ""

    from_host = _FROM.match(from_part)
    by_host = _BY_HOST.match(by_part)
    protocol = _WITH.search(by_part)

    moment = _parse_timestamp(timestamp_text) if timestamp_text else None

    hop = {
        "from_host": _clean(from_host.group(1)) if from_host else None,
        "from_ip": _first_valid_ip(from_part),
        "by_host": _clean(by_host.group(1)) if by_host else None,
        "protocol": _clean(protocol.group(1)) if protocol else None,
        "timestamp": moment.isoformat() if moment else None,
        "delay_seconds": None,
    }
    return hop, moment


def parse_received_chain(received_headers) -> Tuple[List[dict], Optional[str]]:
    """
    Returns (hops, origin_ip). Hops are in chronological order, oldest first.
    Never raises on malformed headers.
    """
    headers = list(received_headers or [])
    # Keep the oldest hops if there are absurdly many
    headers = headers[-MAX_HOPS:]

    hops: List[dict] = []
    moments: List[Optional[object]] = []

    for header in reversed(headers):
        try:
            hop, moment = _parse_hop(header)
        except Exception:
            hop, moment = {
                "from_host": None, "from_ip": None, "by_host": None,
                "protocol": None, "timestamp": None, "delay_seconds": None,
            }, None
        hop["hop"] = len(hops) + 1
        hops.append(hop)
        moments.append(moment)

    for index in range(1, len(hops)):
        previous, current = moments[index - 1], moments[index]
        if previous is None or current is None:
            continue
        try:
            hops[index]["delay_seconds"] = int(
                (current - previous).total_seconds()
            )
        except TypeError:   # naive vs timezone-aware timestamps
            continue

    origin_ip = next(
        (hop["from_ip"] for hop in hops
         if hop["from_ip"] and not is_internal_ip(hop["from_ip"])),
        None,
    )

    return hops, origin_ip


def analyze_received_chain(hops: List[dict]) -> List[dict]:
    """HDR-007: timestamps that go backwards along the delivery path."""
    backwards = [
        {"hop": hop["hop"], "delay_seconds": hop["delay_seconds"]}
        for hop in hops
        if hop.get("delay_seconds") is not None
        and hop["delay_seconds"] < -OUT_OF_ORDER_TOLERANCE_SECONDS
    ]
    if not backwards:
        return []

    return [{
        "signal_id": "HDR-007",
        "category": "header",
        "severity": "low",
        "description": "Received-header timestamps are out of order "
                       "(clock skew or tampered headers)",
        "evidence": {"hops": backwards[:5]},
    }]
