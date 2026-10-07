import networkx as nx
from correlation.models import RelatedCase

# Different shared things carry different weight as evidence.
# A shared hash is strong. A shared big ASN (like Cloudflare) is very weak.
CONFIDENCE = {"hash": 0.9, "ip": 0.7, "domain": 0.7, "asn": 0.2}


def merge_into(master: nx.DiGraph, case_graph: nx.DiGraph) -> None:
    """Add one case's graph into the shared master graph."""
    master.add_nodes_from(case_graph.nodes(data=True))
    master.add_edges_from(case_graph.edges(data=True))


def find_related_cases(master: nx.DiGraph, case_id: str) -> list[RelatedCase]:
    """Find other cases that share an entity with this case."""
    related = {}

    # walk every node this case is connected to (up to 3 hops: domain -> ip -> asn)
    reachable = nx.single_source_shortest_path_length(master, case_id, cutoff=3)

    for node in reachable:
        node_type = master.nodes[node].get("type")
        if node_type in (None, "case"):
            continue
        # which cases point at (or through) this same node?
        for ancestor in nx.ancestors(master, node):
            if master.nodes[ancestor].get("type") == "case" and ancestor != case_id:
                conf = CONFIDENCE.get(node_type, 0.1)
                # keep only the strongest shared evidence per case
                if ancestor not in related or conf > related[ancestor].confidence:
                    related[ancestor] = RelatedCase(
                        case_id=ancestor, shared=node, confidence=conf
                    )

    return sorted(related.values(), key=lambda r: r.confidence, reverse=True)