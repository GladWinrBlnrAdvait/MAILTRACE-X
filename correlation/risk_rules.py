from correlation.allowlist import is_allowlisted_domain

# Placeholder list: TLDs often seen in low-cost phishing domains.
# A TLD is only a weak hint, never proof, so it adds a small score.
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "support",
              "work", "gq", "tk", "ml", "cf", "ga", "rest", "monster"}

NXDOMAIN_POINTS = 30
LOOKUP_FAILED_POINTS = 5
RISKY_TLD_POINTS = 15


def score_domain(domain: str, dns_info: dict) -> tuple[int, list[str]]:
    """Simple, explainable domain risk. Returns (score 0-100, reasons)."""
    if is_allowlisted_domain(domain):
        return 0, []

    score, reasons = 0, []
    status = dns_info.get("status")

    if status == "nxdomain":
        score += NXDOMAIN_POINTS
        reasons.append("Domain does not exist (NXDOMAIN)")
    elif status in ("timeout", "error"):
        score += LOOKUP_FAILED_POINTS
        reasons.append("DNS lookup failed, so the domain could not be verified")

    tld = domain.lower().rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        score += RISKY_TLD_POINTS
        reasons.append(f"Domain uses a TLD often abused in phishing (.{tld})")

    return min(score, 100), reasons


def score_ip(rep: dict) -> tuple[int, list[str]]:
    """IP risk comes from the reputation service (AbuseIPDB score 0-100)."""
    if rep.get("status") != "ok":
        return 0, []
    score = int(rep.get("abuse_score", 0))
    if score <= 0:
        return 0, []
    return score, [f"AbuseIPDB confidence score {score}/100 "
                   f"({rep.get('total_reports', 0)} reports in 90 days)"]
