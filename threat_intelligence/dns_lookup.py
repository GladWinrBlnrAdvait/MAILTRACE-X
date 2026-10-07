import dns.resolver
import dns.exception
from functools import lru_cache


RECORD_TYPES = ["A", "AAAA", "MX", "NS"]

@lru_cache(maxsize=1024)
def resolve_domain(domain: str) -> dict:
    """Look up DNS records for a domain. Never crashes; always returns a dict."""
    result = {"domain": domain, "status": "ok", "A": [], "AAAA": [], "MX": [], "NS": []}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5   # give up after 5 seconds

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            result[rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"      # domain doesn't exist
            break
        except dns.resolver.NoAnswer:
            continue                            # exists, but no record of this type
        except dns.exception.Timeout:
            result["status"] = "timeout"
            break
        except dns.resolver.NoNameservers:
            result["status"] = "error"
            break

    return result