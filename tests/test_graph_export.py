import unittest

from correlation.export import export_graph

HASH = "c" * 64

SAMPLE = {
    "case_id": "CASE-A",
    "entities": [
        {"type": "domain", "value": "evil.test", "risk": 30},
        {"type": "ip", "value": "203.0.113.10", "risk": 0},
        {"type": "asn", "value": "AS64500", "risk": 0},
        {"type": "hash", "value": HASH, "risk": 90},
    ],
    "relationships": [
        {"source": "CASE-A", "relation": "contains", "target": "evil.test"},
        {"source": "evil.test", "relation": "resolves_to", "target": "203.0.113.10"},
        {"source": "203.0.113.10", "relation": "belongs_to", "target": "AS64500"},
        {"source": "CASE-A", "relation": "contains", "target": HASH},
    ],
    "related_cases": [
        {"case_id": "CASE-B", "shared": HASH, "confidence": 0.9, "all_shared": [HASH]},
    ],
}


class GraphExportTests(unittest.TestCase):
    def setUp(self):
        self.graph = export_graph(SAMPLE)
        self.ids = [n["id"] for n in self.graph["nodes"]]

    def test_every_edge_points_at_an_existing_node(self):
        for edge in self.graph["edges"]:
            self.assertIn(edge["source"], self.ids)
            self.assertIn(edge["target"], self.ids)

    def test_node_ids_are_unique(self):
        self.assertEqual(len(self.ids), len(set(self.ids)))

    def test_types_and_risk_are_carried_over(self):
        by_id = {n["id"]: n for n in self.graph["nodes"]}
        self.assertEqual(by_id["CASE-A"]["type"], "case")
        self.assertEqual(by_id["evil.test"]["risk"], 30)
        self.assertEqual(by_id[HASH]["risk"], 90)

    def test_hash_label_is_shortened_but_id_is_full(self):
        by_id = {n["id"]: n for n in self.graph["nodes"]}
        self.assertEqual(len(by_id[HASH]["label"]), 13)
        self.assertEqual(by_id[HASH]["id"], HASH)

    def test_related_case_becomes_a_node_and_an_edge(self):
        self.assertIn("CASE-B", self.ids)
        related = [e for e in self.graph["edges"] if e["relation"] == "related_to"]
        self.assertEqual(len(related), 1)
        self.assertEqual(related[0]["confidence"], 0.9)

    def test_case_without_relationships_still_exports(self):
        graph = export_graph({"case_id": "CASE-X"})
        self.assertEqual(graph["nodes"], [{"id": "CASE-X", "type": "case", "label": "CASE-X", "risk": 0}])
        self.assertEqual(graph["edges"], [])


if __name__ == "__main__":
    unittest.main()
