import networkx as nx
from correlation.models import RelatedCase
from correlation.allowlist import is_allowlisted_domain, is_allowlisted_asn

# Hand-picked placeholder weights: a hash is nearly unique,
# an IP or domain can be reused, an ASN is a huge network.
CONFIDENCE = {"hash": 0.9, "ip": 0.7, "domain": 0.7, "asn": 0.2}


def merge_into(master: nx.DiGraph, case_graph: nx.DiGraph) -> None:
    """Add one case's graph into the shared master graph."""
    master.add_nodes_from(case_graph.nodes(data=True))
    master.add_edges_from(case_graph.edges(data=True))


def _is_ignored(master: nx.DiGraph, node: str, node_type: str) -> bool:
    """True if this node is well-known infrastructure and shouldn't link cases."""
    if node_type == "domain":
        return is_allowlisted_domain(node)
    if node_type == "asn":
        return is_allowlisted_asn(node)
    if node_type == "ip":
        # an IP is ignored if it belongs to an allowlisted network
        return any(
            master.nodes[n].get("type") == "asn" and is_allowlisted_asn(n)
            for n in master.successors(node)
        )
    return False


def find_related_cases(master: nx.DiGraph, case_id: str) -> list[RelatedCase]:
    """Find other cases sharing an entity with this case."""
    shared_by_case = {}   # other_case_id -> {shared_node: confidence}

    reachable = nx.single_source_shortest_path_length(master, case_id, cutoff=3)

    for node in reachable:
        node_type = master.nodes[node].get("type")
        if node_type in (None, "case"):
            continue
        if _is_ignored(master, node, node_type):
            continue

        confidence = CONFIDENCE.get(node_type, 0.1)
        for ancestor in nx.ancestors(master, node):
            if master.nodes[ancestor].get("type") == "case" and ancestor != case_id:
                shared_by_case.setdefault(ancestor, {})[node] = confidence

    related = []
    for other_case, shared in shared_by_case.items():
        best = max(shared, key=shared.get)   # the strongest shared item
        related.append(RelatedCase(
            case_id=other_case,
            shared=best,
            confidence=shared[best],
            all_shared=sorted(shared),
        ))

    return sorted(related, key=lambda r: r.confidence, reverse=True)