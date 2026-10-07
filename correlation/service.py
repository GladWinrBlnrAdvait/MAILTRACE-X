import networkx as nx
from correlation.graph_builder import build_case_graph
from correlation.correlator import merge_into, find_related_cases
from correlation.models import CorrelatedThreatData

_master = nx.DiGraph()


def enrich_evidence(evidence) -> CorrelatedThreatData:
    """Input: EmailEvidence. Output: CorrelatedThreatData."""
    case_graph, output = build_case_graph(evidence)
    merge_into(_master, case_graph)
    output.related_cases = find_related_cases(_master, evidence.case_id)
    return output

def get_related_cases(case_id: str):
    """Look up related cases at any time, including ones added after this case."""
    if case_id not in _master:
        return []
    return find_related_cases(_master, case_id)