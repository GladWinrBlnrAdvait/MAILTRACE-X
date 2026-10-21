import json

r2 = json.load(open("r2.json", encoding="utf-8"))["data"]
print("verdicts:", r2["verdicts"])
print("verdict_labels:", r2["verdict_labels"])
print("verdict_confidence:", r2["verdict_confidence"])
print("technique sample:", r2["mitre_attack_techniques"][:3])
print("ids sample:", r2["ids_alerts"][:1])
print("ip sample:", r2["ip_traffic"][:2])