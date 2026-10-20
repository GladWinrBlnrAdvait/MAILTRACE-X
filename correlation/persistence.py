import networkx as nx


def graph_from_correlation(data: dict) -> nx.DiGraph:
    """Rebuild one case's graph from its saved CorrelatedThreatData (a plain dict).

    The saved entities tell us each node's type, and the saved relationships
    tell us the edges, which is everything correlation needs.
    """
    G = nx.DiGraph()
    G.add_node(data["case_id"], type="case")
    for entity in data.get("entities", []):
        G.add_node(entity["value"], type=entity["type"], risk=entity.get("risk", 0))
    for rel in data.get("relationships", []):
        G.add_edge(rel["source"], rel["target"], relation=rel["relation"])
    return G
