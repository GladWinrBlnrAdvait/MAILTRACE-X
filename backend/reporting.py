from html import escape
from io import BytesIO


def build_html_report(result: dict) -> str:
    """Generate a self-contained analyst report suitable for a browser or export."""
    risk, detection, evidence = result["risk"], result["detection"], result["evidence"]
    metadata = evidence["metadata"]
    reasons = "".join(f"<li>{escape(reason)}</li>" for reason in risk["reasons"])
    indicators = "".join(f"<code>{escape(value)}</code> " for value in evidence["iocs"]["urls"] + evidence["iocs"]["domains"] + evidence["iocs"]["ips"])
    signals = "".join(f"<tr><td>{escape(str(item.get('signal_id', '—')))}</td><td>{escape(str(item.get('severity', 'unknown')))}</td><td>{escape(str(item.get('description', 'Security anomaly detected')))}</td></tr>" for item in evidence.get("evidence_signals", [])) or "<tr><td colspan='3'>No evidence signals recorded.</td></tr>"
    auth = evidence.get("authentication", {})
    attachments = evidence.get("attachments", [])
    attachment_rows = "".join(f"<tr><td>{escape(str(item.get('filename', 'unnamed')))}</td><td>{escape(str(item.get('mime_type', 'unknown')))}</td><td>{escape(str(item.get('sha256', '')))}</td></tr>" for item in attachments) or "<tr><td colspan='3'>No attachments found.</td></tr>"
    correlation = result.get("correlation") or {}
    related = correlation.get("related_cases", [])
    related_rows = "".join(f"<li>{escape(str(item.get('case_id', item)))}</li>" for item in related) or "<li>No related cases identified.</li>"
    terms = "".join(f"<code>{escape(term)}: {weight:+.2f}</code> " for term, weight in detection.get("term_contributions", {}).items()) or "<p>No lexical terms contributed.</p>"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>MAILTRACE-X report</title>
    <style>body{{font-family:Arial,sans-serif;background:#09111f;color:#e8edf7;max-width:850px;margin:40px auto;padding:28px}} .card{{background:#111d31;padding:22px;border-radius:16px;margin:16px 0}} .risk{{font-size:44px;color:#ff6b6b}} code{{display:inline-block;background:#20314d;padding:5px;margin:4px;border-radius:5px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:8px;border-bottom:1px solid #304563;text-align:left;word-break:break-word}}@media print{{body{{background:#fff;color:#111}}.card{{background:#fff;border:1px solid #ddd}}}}</style></head>
    <body><h1>MAILTRACE-X <small>Investigation Report</small></h1><div class='card'><div>CASE {escape(result['case_id'])}</div><div class='risk'>{risk['score']}/100 · {risk['level'].upper()}</div><p>{detection['classification'].upper()} · {detection['phishing_probability']:.0%} phishing probability · {risk['confidence']:.0%} confidence</p></div>
    <div class='card'><h2>Email summary</h2><p><b>From:</b> {escape(metadata.get('sender') or 'Unknown')}<br><b>Subject:</b> {escape(metadata.get('subject') or 'No subject')}</p></div>
    <div class='card'><h2>Evidence</h2><ul>{reasons}</ul><table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{signals}</tbody></table></div>
    <div class='card'><h2>Authentication results</h2><p>SPF: <b>{escape(auth.get('spf', 'unknown'))}</b> · DKIM: <b>{escape(auth.get('dkim', 'unknown'))}</b> · DMARC: <b>{escape(auth.get('dmarc', 'unknown'))}</b></p></div>
    <div class='card'><h2>Indicators</h2>{indicators or '<p>None extracted</p>'}</div><div class='card'><h2>Attachment and sandbox findings</h2><table><thead><tr><th>Attachment</th><th>Type</th><th>SHA-256</th></tr></thead><tbody>{attachment_rows}</tbody></table><p>Attachments are metadata-only findings; this platform does not execute them.</p></div>
    <div class='card'><h2>Threat graph and related cases</h2><ul>{related_rows}</ul></div><div class='card'><h2>Top contributing terms</h2>{terms}</div></body></html>"""


def build_pdf_report(result: dict) -> bytes:
    """Create a small PDF using structured evidence only (never the raw body)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen.canvas import Canvas
    output, y = BytesIO(), 750
    canvas = Canvas(output, pagesize=letter)
    canvas.setTitle(f"MAILTRACE-X report {result['case_id']}")
    lines = [
        "MAILTRACE-X Investigation Report", f"Case: {result['case_id']}",
        f"Risk: {result['risk']['score']}/100 ({result['risk']['level'].upper()})",
        f"Verdict: {result['detection']['classification'].upper()} ({result['detection']['phishing_probability']:.0%})",
        "Authentication: " + ", ".join(f"{k.upper()}={v}" for k, v in result['evidence'].get('authentication', {}).items()),
        "Evidence: " + "; ".join(result['risk'].get('reasons', [])),
    ]
    for line in lines:
        words, current = line.split(), ""
        for word in words:
            if stringWidth(f"{current} {word}", "Helvetica", 10) > 520:
                canvas.drawString(48, y, current); y -= 16; current = word
            else: current = f"{current} {word}".strip()
        canvas.drawString(48, y, current); y -= 20
        if y < 60: canvas.showPage(); y = 750
    canvas.save()
    return output.getvalue()
