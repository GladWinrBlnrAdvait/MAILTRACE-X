import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as LookupTimeout

import networkx as nx

from correlation.models import CorrelatedThreatData, Entity, Relationship
from correlation.risk_rules import score_domain, score_hash, score_ip
from threat_intelligence.dns_lookup import resolve_domain
from threat_intelligence.hash_reputation import check_hash_reputation
from threat_intelligence.ip_lookup import lookup_ip
from threat_intelligence.reputation import check_ip_reputation

CASE_TIME_BUDGET = 25   # seconds allowed for all network lookups of one case


def _dns_failed(domain: str, status: str) -> dict:
    return {"domain": domain, "status": status, "A": [], "AAAA": [], "MX": [], "NS": []}


def _ip_failed(ip: str, status: str) -> dict:
    return {"ip": ip, "status": status, "asn": None, "asn_description": None,
            "country": None, "network": None, "org": None}


def _hash_failed(sha256: str, status: str) -> dict:
    return {"sha256": sha256, "status": status, "found": False,
            "signature": None, "file_type": None, "tags": []}


def _run_parallel(func, items, deadline, on_failure, workers=8):
    """Run func(item) for every item at once; anything unfinished at the deadline
    gets a 'timeout' placeholder instead of blocking the whole case."""
    results = {}
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {item: pool.submit(func, item) for item in items}
    for item, future in futures.items():
        try:
            results[item] = future.result(timeout=max(0.0, deadline - time.monotonic()))
        except LookupTimeout:
            results[item] = on_failure(item, "timeout")
        except Exception:
            results[item] = on_failure(item, "error")
    pool.shutdown(wait=False, cancel_futures=True)   # don't wait for stragglers
    return results


def build_case_graph(evidence, time_budget: float = CASE_TIME_BUDGET):
    """Enrich all IOCs of one case, build its graph and fill the output contract."""
    G = nx.DiGraph()
    entities, relationships = [], []
    case_id = evidence.case_id
    deadline = time.monotonic() + time_budget
    G.add_node(case_id, type="case")

    def link(source, relation, target):
        G.add_edge(source, target, relation=relation)
        relationships.append(Relationship(source=source, relation=relation, target=target))

    email_ips = set(evidence.iocs.ips)
    all_ips = set(email_ips)
    seen_asns = set()

    # 1. Domains -> DNS (all domains looked up in parallel)
    domains = sorted(evidence.iocs.domains)
    dns_results = _run_parallel(resolve_domain, domains, deadline,
                                lambda d, status: _dns_failed(d, status))
    for domain in domains:
        dns_info = dns_results[domain]
        risk, reasons = score_domain(domain, dns_info)
        G.add_node(domain, type="domain", status=dns_info["status"], risk=risk)
        entities.append(Entity(type="domain", value=domain, risk=risk,
                               details=dns_info, risk_reasons=reasons))
        link(case_id, "contains", domain)
        for ip in sorted(dns_info["A"]):
            all_ips.add(ip)
            link(domain, "resolves_to", ip)

    # 2. IPs -> RDAP + reputation (all IPs in parallel)
    ips = sorted(all_ips)
    rdap_results = _run_parallel(lookup_ip, ips, deadline,
                                 lambda ip, status: _ip_failed(ip, status))
    rep_results = _run_parallel(check_ip_reputation, ips, deadline,
                                lambda ip, status: {"ip": ip, "status": status,
                                                    "abuse_score": 0, "total_reports": 0})
    for ip in ips:
        info, rep = rdap_results[ip], rep_results[ip]
        risk, reasons = score_ip(rep)
        G.add_node(ip, type="ip", risk=risk)
        entities.append(Entity(type="ip", value=ip, risk=risk,
                               details={**info, "reputation": rep}, risk_reasons=reasons))
        if ip in email_ips:
            link(case_id, "contains", ip)

        asn = info.get("asn")
        if asn:
            G.add_node(asn, type="asn")
            link(ip, "belongs_to", asn)
            if asn not in seen_asns:
                seen_asns.add(asn)
                entities.append(Entity(type="asn", value=asn,
                                       details={"description": info.get("asn_description")}))

    # 3. Attachments -> hashes (reputation lookups in parallel)
    attachments = {a.sha256: a for a in evidence.attachments if a.sha256}
    hash_results = _run_parallel(check_hash_reputation, sorted(attachments), deadline,
                                 lambda h, status: _hash_failed(h, status))
    for sha256, att in attachments.items():
        rep = hash_results[sha256]
        risk, reasons = score_hash(rep)
        G.add_node(sha256, type="hash", risk=risk)
        link(case_id, "contains", sha256)
        entities.append(Entity(type="hash", value=sha256, risk=risk, risk_reasons=reasons,
                               details={"filename": att.filename,
                                        "mime_type": getattr(att, "mime_type", None),
                                        "size_bytes": getattr(att, "size_bytes", None),
                                        "reputation": rep}))

    output = CorrelatedThreatData(case_id=case_id, entities=entities,
                                  relationships=relationships)
    return G, output
