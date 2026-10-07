import sys
from evidence.email_parser import parse_email
from correlation.service import enrich_evidence, get_related_cases

paths = sys.argv[1:]
results = []

for i, path in enumerate(paths, start=1):
    evidence = parse_email(path, case_id=f"CASE-{i:03d}")
    result = enrich_evidence(evidence)
    results.append(result)
    print(result.model_dump_json(indent=2))

print("\n--- Related cases ---")
for r in results:
    for rel in r.related_cases:
        print(f"{r.case_id} <-> {rel.case_id} via {rel.shared} ({rel.confidence})")


print("\n--- Related cases (final) ---")
for r in results:
    for rel in get_related_cases(r.case_id):
        print(f"{r.case_id} <-> {rel.case_id} via {rel.shared} ({rel.confidence})")

import json, os
os.makedirs("docs", exist_ok=True)

for r in results:
    r.related_cases = get_related_cases(r.case_id)   # refresh with final data

with open("docs/sample_correlated_output.json", "w", encoding="utf-8") as f:
    json.dump([r.model_dump() for r in results], f, indent=2)