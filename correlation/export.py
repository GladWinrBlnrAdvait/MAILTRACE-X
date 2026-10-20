from correlation.persistence import graph_from_correlation


def _label(node_type: str, value: str) -> str:
    """Short, readable text for the dashboard (full value stays in 'id')."""
    return value[:12] + "…" if node_type == "hash" else value


def export_graph(correlation: dict) -> dict:
    """Turn saved CorrelatedThreatData into {"nodes": [...], "edges": [...]} JSON.

    Related cases are added as extra 'case' nodes joined by 'related_to' edges,
    so the dashboard can draw the whole picture from one response.
    """
    graph = graph_from_correlation(correlation)
    case_id = correlation["case_id"]

    nodes = [
        {"id": node, "type": data.get("type", "unknown"),
         "label": _label(data.get("type", "unknown"), node), "risk": data.get("risk", 0)}
        for node, data in sorted(graph.nodes(data=True))
    ]
    edges = [
        {"source": source, "target": target, "relation": data.get("relation")}
        for source, target, data in graph.edges(data=True)
    ]

    known = set(graph.nodes)
    for related in correlation.get("related_cases", []):
        other = related["case_id"]
        if other not in known:
            nodes.append({"id": other, "type": "case", "label": other, "risk": 0})
            known.add(other)
        edges.append({
            "source": case_id, "target": other, "relation": "related_to",
            "confidence": related["confidence"],
            "shared": related.get("all_shared") or [related["shared"]],
        })

    return {"case_id": case_id, "nodes": nodes, "edges": edges}
