import threading

import networkx as nx

from correlation.correlator import merge_into, find_related_cases
from correlation.graph_builder import build_case_graph
from correlation.models import CorrelatedThreatData
from correlation.persistence import graph_from_correlation

_master = nx.DiGraph()
_lock = threading.Lock()   # the API may run several requests at once


def enrich_evidence(evidence) -> CorrelatedThreatData:
    """Input: EmailEvidence. Output: CorrelatedThreatData."""
    case_graph, output = build_case_graph(evidence)   # slow part, no lock needed
    with _lock:                                       # graph edits must not overlap
        merge_into(_master, case_graph)
        output.related_cases = find_related_cases(_master, evidence.case_id)
    return output


def get_related_cases(case_id: str):
    """Look up related cases at any time, including ones added after this case."""
    with _lock:
        if case_id not in _master:
            return []
        return find_related_cases(_master, case_id)


def load_cases(stored_cases) -> int:
    """Rebuild the shared graph from previously saved analysis results.

    Call once at server start-up. Each item is a saved result dict that
    contains a 'correlation' entry. Returns how many cases were loaded.
    """
    loaded = 0
    with _lock:
        for stored in stored_cases:
            correlation = (stored or {}).get("correlation")
            if correlation:
                merge_into(_master, graph_from_correlation(correlation))
                loaded += 1
    return loaded
