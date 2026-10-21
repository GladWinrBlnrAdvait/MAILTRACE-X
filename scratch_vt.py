import json
r2 = json.load(open("r2.json"))["data"]
print("verdicts:", r2["verdicts"])
print("verdict_labels:", r2["verdict_labels"])
print("verdict_confidence:", r2["verdict_confidence"])
print("technique sample:", r2["mitre_attack_techniques"][:3])
print("ids sample:", r2["ids_alerts"][:1])
print("ip sample:", r2["ip_traffic"][:2])

def show(obj, depth=0, max_depth=3, name="root"):
    """Print the structure of a JSON object, not all the data."""
    pad = "  " * depth
    if isinstance(obj, dict):
        print(f"{pad}{name}: dict ({len(obj)} keys)")
        if depth < max_depth:
            for key, value in list(obj.items())[:25]:
                show(value, depth + 1, max_depth, key)
    elif isinstance(obj, list):
        print(f"{pad}{name}: list ({len(obj)} items)")
        if obj and depth < max_depth:
            show(obj[0], depth + 1, max_depth, "[0]")
    else:
        print(f"{pad}{name}: {type(obj).__name__} = {str(obj)[:60]!r}")

for filename in ("r1.json", "r2.json", "r3.json"):
    print("=" * 60, filename)
    with open(filename) as handle:
        show(json.load(handle), max_depth=3)

