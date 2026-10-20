from html import escape


def build_html_report(result: dict) -> str:
    """Generate a self-contained analyst report suitable for a browser or export."""
    risk, detection, evidence = result["risk"], result["detection"], result["evidence"]
    metadata = evidence["metadata"]
    reasons = "".join(f"<li>{escape(reason)}</li>" for reason in risk["reasons"])
    indicators = "".join(f"<code>{escape(value)}</code> " for value in evidence["iocs"]["urls"] + evidence["iocs"]["domains"] + evidence["iocs"]["ips"])
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>MAILTRACE-X report</title>
    <style>body{{font-family:Arial,sans-serif;background:#09111f;color:#e8edf7;max-width:850px;margin:40px auto;padding:28px}} .card{{background:#111d31;padding:22px;border-radius:16px;margin:16px 0}} .risk{{font-size:44px;color:#ff6b6b}} code{{display:inline-block;background:#20314d;padding:5px;margin:4px;border-radius:5px}}</style></head>
    <body><h1>MAILTRACE-X <small>Investigation Report</small></h1><div class='card'><div>CASE {escape(result['case_id'])}</div><div class='risk'>{risk['score']}/100 · {risk['level'].upper()}</div><p>{detection['classification'].upper()} · {detection['phishing_probability']:.0%} phishing probability · {risk['confidence']:.0%} confidence</p></div>
    <div class='card'><h2>Email summary</h2><p><b>From:</b> {escape(metadata.get('sender') or 'Unknown')}<br><b>Subject:</b> {escape(metadata.get('subject') or 'No subject')}</p></div>
    <div class='card'><h2>Evidence</h2><ul>{reasons}</ul></div><div class='card'><h2>Indicators</h2>{indicators or '<p>None extracted</p>'}</div></body></html>"""
