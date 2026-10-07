import networkx as nx
from correlation.models import CorrelatedThreatData, Entity, Relationship
from threat_intelligence.dns_lookup import resolve_domain
from threat_intelligence.ip_lookup import lookup_ip


def build_case_graph(evidence) -> tuple[nx.DiGraph, CorrelatedThreatData]:
    """Enrich all IOCs in one case, build the graph, and fill the output contract."""
    G = nx.DiGraph()
    entities, relationships = [], []
    case_id = evidence.case_id
    G.add_node(case_id, type="case")

    def link(source, relation, target):
        """Add one relationship to both the graph and the output list."""
        G.add_edge(source, target, relation=relation)
        relationships.append(Relationship(source=source, relation=relation, target=target))

    email_ips = set(evidence.iocs.ips)   # IPs found directly in the email
    all_ips = set(email_ips)             # plus IPs found through DNS
    seen_asns = set()

    # Domains -> DNS -> IPs
    for domain in sorted(evidence.iocs.domains):
        dns_info = resolve_domain(domain)
        G.add_node(domain, type="domain", status=dns_info["status"])
        entities.append(Entity(type="domain", value=domain, details=dns_info))
        link(case_id, "contains", domain)

        for ip in sorted(dns_info["A"]):
            all_ips.add(ip)
            link(domain, "resolves_to", ip)

    # IPs -> RDAP -> ASN
    for ip in sorted(all_ips):
        info = lookup_ip(ip)
        G.add_node(ip, type="ip")
        entities.append(Entity(type="ip", value=ip, details=info))

        if ip in email_ips:
            link(case_id, "contains", ip)

        asn = info.get("asn")
        if asn:
            G.add_node(asn, type="asn")
            link(ip, "belongs_to", asn)
            if asn not in seen_asns:
                seen_asns.add(asn)
                entities.append(Entity(
                    type="asn", value=asn,
                    details={"description": info.get("asn_description")},
                ))

    # Attachments -> hashes
    for att in evidence.attachments:
        if att.sha256:
            G.add_node(att.sha256, type="hash")
            link(case_id, "contains", att.sha256)
            entities.append(Entity(
                type="hash", value=att.sha256,
                details={"filename": att.filename,
                         "mime_type": getattr(att, "mime_type", None),
                         "size_bytes": getattr(att, "size_bytes", None)},
            ))

    output = CorrelatedThreatData(
        case_id=case_id, entities=entities, relationships=relationships
    )
    return G, output