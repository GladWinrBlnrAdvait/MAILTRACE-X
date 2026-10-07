import networkx as nx
from correlation.models import CorrelatedThreatData, Entity, Relationship
from threat_intelligence.dns_lookup import resolve_domain
from threat_intelligence.ip_lookup import lookup_ip


def build_case_graph(evidence) -> tuple[nx.DiGraph, CorrelatedThreatData]:
    """Enrich all IOCs in one case and build a graph + the output contract."""
    G = nx.DiGraph()                      # DiGraph = edges have a direction
    entities, relationships = [], []
    seen_ips = set(evidence.iocs.ips)

    case_node = evidence.case_id
    G.add_node(case_node, type="case")

    # Domains -> DNS -> IPs
    for domain in evidence.iocs.domains:
        dns_info = resolve_domain(domain)
        G.add_node(domain, type="domain", **{"status": dns_info["status"]})
        G.add_edge(case_node, domain, relation="contains")
        entities.append(Entity(type="domain", value=domain, details=dns_info))

        for ip in dns_info["A"]:
            seen_ips.add(ip)
            G.add_edge(domain, ip, relation="resolves_to")
            relationships.append(Relationship(source=domain, relation="resolves_to", target=ip))

    # IPs -> RDAP -> ASN
    for ip in seen_ips:
        info = lookup_ip(ip)
        G.add_node(ip, type="ip")
        G.add_edge(case_node, ip, relation="contains")
        entities.append(Entity(type="ip", value=ip, details=info))

        if info["asn"]:
            G.add_node(info["asn"], type="asn")
            G.add_edge(ip, info["asn"], relation="belongs_to")
            relationships.append(Relationship(source=ip, relation="belongs_to", target=info["asn"]))

    # Attachment hashes
    for att in evidence.attachments:
        if att.sha256:
            G.add_node(att.sha256, type="hash")
            G.add_edge(case_node, att.sha256, relation="contains")
            relationships.append(Relationship(source=case_node, relation="contains", target=att.sha256))

    output = CorrelatedThreatData(
        case_id=evidence.case_id, entities=entities, relationships=relationships
    )
    return G, output