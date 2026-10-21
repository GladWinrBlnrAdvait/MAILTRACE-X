"""HTML and polished, evidence-driven PDF reporting for MAILTRACE-X."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
from urllib.parse import urlparse


def build_html_report(result: dict) -> str:
    """Generate a self-contained browser report from the stored analysis payload."""
    risk = result.get("risk") or {}
    detection = result.get("detection") or {}
    evidence = result.get("evidence") or {}
    metadata = evidence.get("metadata") or {}
    iocs = evidence.get("iocs") or {}
    reasons = "".join(f"<li>{escape(str(reason))}</li>" for reason in risk.get("reasons", [])) or "<li>No risk reasons recorded.</li>"
    indicators = "".join(
        f"<tr><td>{escape(kind)}</td><td>{escape(str(value))}</td></tr>"
        for kind, key in (("URL", "urls"), ("Domain", "domains"), ("IP address", "ips"), ("Email address", "emails"))
        for value in iocs.get(key, [])
    ) or "<tr><td colspan='2'>No indicators extracted.</td></tr>"
    signals = "".join(
        f"<tr><td>{escape(str(item.get('signal_id', '—')))}</td><td>{escape(str(item.get('severity', 'unknown')))}</td><td>{escape(str(item.get('description', 'Security anomaly detected')))}</td></tr>"
        for item in evidence.get("evidence_signals", [])
    ) or "<tr><td colspan='3'>No structured evidence signals recorded.</td></tr>"
    auth = evidence.get("authentication") or {}
    attachments = evidence.get("attachments", []) or []
    attachment_rows = "".join(
        f"<tr><td>{escape(str(item.get('filename', 'unnamed')))}</td><td>{escape(str(item.get('mime_type', 'unknown')))}</td><td>{escape(str(item.get('size_bytes', 'unknown')))}</td><td>{escape(str(item.get('sha256', '')))}</td></tr>"
        for item in attachments
    ) or "<tr><td colspan='4'>No attachments found.</td></tr>"
    correlation = result.get("correlation") or {}
    related = correlation.get("related_cases", []) or []
    related_rows = "".join(
        f"<tr><td>{escape(str(item.get('case_id', '—')))}</td><td>{escape(str(item.get('shared', '—')))}</td><td>{escape(', '.join(map(str, item.get('all_shared', []) or [])))}</td><td>{float(item.get('confidence', 0)):.0%}</td></tr>"
        for item in related
    ) or "<tr><td colspan='4'>No related cases identified.</td></tr>"
    terms = "".join(
        f"<code>{escape(str(term))}: {float(weight):+.3f}</code> "
        for term, weight in sorted((detection.get("term_contributions") or {}).items(), key=lambda kv: abs(float(kv[1])), reverse=True)
    ) or "<p>No lexical contributions recorded.</p>"
    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    recipient = ", ".join(map(str, metadata.get("recipients", []) or [])) or "Not present"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>MAILTRACE-X Phishing Analysis Report</title>
    <style>body{{font-family:Arial,sans-serif;background:#f3f7fc;color:#14233d;max-width:1050px;margin:28px auto;padding:24px}}.banner{{background:#103d70;color:#fff;padding:24px;border-radius:12px}}.card{{background:#fff;padding:20px;border:1px solid #d8e3f0;border-radius:12px;margin:14px 0;break-inside:avoid}}.risk{{font-size:34px;font-weight:700;color:#b4232b}}h2{{color:#093b78;font-size:18px}}small,.muted{{color:#53657d}}code{{display:inline-block;background:#eaf2fb;padding:5px;margin:3px;border-radius:4px;overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}td,th{{padding:8px;border:1px solid #d8e3f0;text-align:left;vertical-align:top;overflow-wrap:anywhere;font-size:12px}}th{{background:#eaf2f9}}@media print{{body{{background:#fff;margin:0;padding:8px}}.card{{break-inside:avoid}}}}</style></head>
    <body><div class='banner'><h1>Phishing Analysis Report</h1><div>Security Threat Detection and Investigation</div><p>Report ID: {escape(str(result.get('case_id', 'Unknown')))} &nbsp;|&nbsp; Generated: {escape(generated)} &nbsp;|&nbsp; Analyst: Automated Analysis System</p></div>
    <div class='card'><h2>Case summary and risk assessment</h2><div class='risk'>{int(risk.get('score', 0))}/100 · {escape(str(risk.get('level', 'unknown')).upper())}</div><p><b>Case ID:</b> {escape(str(result.get('case_id', 'Unknown')))}<br><b>Classification:</b> {escape(str(detection.get('classification', 'unknown')).upper())}<br><b>Phishing probability:</b> {float(detection.get('phishing_probability', 0)):.0%}<br><b>Confidence:</b> {float(risk.get('confidence', 0)):.0%}</p><h3>Risk reasons</h3><ul>{reasons}</ul></div>
    <div class='card'><h2>Email summary</h2><p><b>Sender:</b> {escape(str(metadata.get('sender') or 'Not present'))}<br><b>Recipients:</b> {escape(recipient)}<br><b>Subject:</b> {escape(str(metadata.get('subject') or 'Not present'))}<br><b>Date:</b> {escape(str(metadata.get('date') or 'Not present'))}<br><b>Reply-To:</b> {escape(str(metadata.get('reply_to') or 'Not present'))}<br><b>Return-Path:</b> {escape(str(metadata.get('return_path') or 'Not present'))}<br><b>Message ID:</b> {escape(str(metadata.get('message_id') or 'Not present'))}</p></div>
    <div class='card'><h2>Evidence and security findings</h2><table><thead><tr><th style='width:14%'>Finding ID</th><th style='width:15%'>Severity</th><th>Finding</th></tr></thead><tbody>{signals}</tbody></table></div>
    <div class='card'><h2>Email authentication</h2><p>Reported header results only. MAILTRACE-X parses existing authentication headers and does not independently validate SPF, DKIM or DMARC.</p><table><tr><th>SPF</th><th>DKIM</th><th>DMARC</th></tr><tr><td>{escape(str(auth.get('spf', 'unknown')).upper())}</td><td>{escape(str(auth.get('dkim', 'unknown')).upper())}</td><td>{escape(str(auth.get('dmarc', 'unknown')).upper())}</td></tr></table></div>
    <div class='card'><h2>Indicators of compromise (IOCs)</h2><table><thead><tr><th style='width:20%'>Type</th><th>Extracted value</th></tr></thead><tbody>{indicators}</tbody></table><p class='muted'>Extraction is not proof that every listed indicator is malicious.</p></div>
    <div class='card'><h2>Attachment findings</h2><table><thead><tr><th>Filename</th><th>MIME type</th><th>Size (bytes)</th><th>SHA-256</th></tr></thead><tbody>{attachment_rows}</tbody></table><p class='muted'>Attachments are hashed and enriched when configured; they are not executed. An unknown hash is not proof of safety.</p></div>
    <div class='card'><h2>Threat relationships</h2><table><thead><tr><th>Related case</th><th>Shared indicator</th><th>All shared indicators</th><th>Confidence</th></tr></thead><tbody>{related_rows}</tbody></table></div>
    <div class='card'><h2>Detection explanation</h2><p><b>Model:</b> {escape(str(detection.get('model', 'unknown')))}</p><h3>Top contributing words and text features</h3>{terms}</div>
    <div class='card'><h2>Analysis summary</h2><p>Automated analysis classified this email as <b>{escape(str(detection.get('classification', 'unknown')).upper())}</b>, with a phishing probability of {float(detection.get('phishing_probability', 0)):.0%} and a risk score of {int(risk.get('score', 0))}/100 ({escape(str(risk.get('level', 'unknown')).upper())}). This report reflects only the evidence and enrichment results available at generation time.</p><p><b>Recommended handling:</b> {escape(_recommendation(detection.get('classification', 'unknown'), risk.get('level', 'unknown')))}</p></div>
    </body></html>"""


def _recommendation(classification: str, level: str) -> str:
    classification = str(classification).lower()
    level = str(level).lower()
    if classification == "phishing" or level in {"critical", "high"}:
        return "Do not click links or open unexpected attachments. Verify the request through a trusted channel and follow your organisation's incident response process."
    if classification == "suspicious" or level == "medium":
        return "Treat the message with caution. Verify the sender and any requested action through a trusted channel before interacting."
    return "No strong phishing verdict was produced by this analysis, but this is not a guarantee of safety. Verify unexpected requests independently."


def build_pdf_report(result: dict) -> bytes:
    """Create a paginated, structured forensic PDF using only this case's actual data."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        CondPageBreak, Flowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    navy = colors.HexColor("#0B376A")
    blue = colors.HexColor("#0757B8")
    bright_blue = colors.HexColor("#0879E8")
    light_blue = colors.HexColor("#EAF3FB")
    pale = colors.HexColor("#F5F8FC")
    border = colors.HexColor("#D9E5F1")
    ink = colors.HexColor("#152644")
    muted = colors.HexColor("#536782")
    red = colors.HexColor("#D92D36")
    pale_red = colors.HexColor("#FDEBEC")
    amber = colors.HexColor("#B86A00")
    pale_amber = colors.HexColor("#FFF2D6")
    green = colors.HexColor("#087F5B")
    pale_green = colors.HexColor("#E1F7EE")
    white = colors.white

    result = result or {}
    risk = result.get("risk") or {}
    detection = result.get("detection") or {}
    evidence = result.get("evidence") or {}
    metadata = evidence.get("metadata") or {}
    iocs = evidence.get("iocs") or {}
    auth = evidence.get("authentication") or {}
    correlation = result.get("correlation") or {}
    signals = evidence.get("evidence_signals") or []
    attachments = evidence.get("attachments") or []
    related_cases = correlation.get("related_cases") or []
    graph_relationships = correlation.get("relationships") or []
    entities = correlation.get("entities") or []

    case_id = str(result.get("case_id") or "Unknown case")
    created_raw = result.get("created_at")
    generated_dt = datetime.now(timezone.utc)
    generated = generated_dt.strftime("%d %b %Y, %H:%M UTC")
    created = str(created_raw or "Not recorded")
    if created_raw:
        try:
            parsed_created = datetime.fromisoformat(str(created_raw).replace("Z", "+00:00"))
            if parsed_created.tzinfo is None:
                parsed_created = parsed_created.replace(tzinfo=timezone.utc)
            created = parsed_created.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
        except (ValueError, TypeError):
            pass

    def safe(value, fallback="Not provided"):
        if value is None or value == "":
            value = fallback
        return escape(str(value)).replace("\n", "<br/>")

    def para(value, style="Body", fallback="Not provided"):
        return Paragraph(safe(value, fallback), styles[style])

    def pill_color(value):
        val = str(value or "unknown").strip().lower()
        if val in {"critical", "high", "fail", "phishing", "found", "malicious"}:
            return red, pale_red
        if val in {"medium", "softfail", "temperror", "permerror", "unknown", "none", "neutral", "not checked", "lookup_failed", "no_api_key"}:
            return amber, pale_amber
        if val in {"low", "pass", "legitimate", "ok", "benign"}:
            return green, pale_green
        return muted, pale

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.6, leading=9.5, textColor=ink, spaceAfter=0, splitLongWords=1))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.7, leading=8.2, textColor=muted, splitLongWords=1))
    styles.add(ParagraphStyle(name="TableHead", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.2, leading=8.5, textColor=navy, splitLongWords=1))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.0, leading=8.5, textColor=ink, splitLongWords=1, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellBold", parent=styles["Cell"], fontName="Helvetica-Bold", textColor=navy))
    styles.add(ParagraphStyle(name="CardTitle", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=10.0, leading=12, textColor=navy, spaceAfter=0))
    styles.add(ParagraphStyle(name="SectionNumber", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=9.0, leading=10, textColor=white, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="Scope", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.2, leading=9.5, textColor=muted))
    styles.add(ParagraphStyle(name="RiskValue", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=12.5, leading=14.5, textColor=red))
    styles.add(ParagraphStyle(name="Verdict", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=9.2, leading=11, textColor=navy))
    styles.add(ParagraphStyle(name="TableSmall", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.5, leading=7.8, textColor=ink, splitLongWords=1, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="TableSmallHead", parent=styles["TableHead"], fontSize=6.8, leading=8, wordWrap="CJK"))

    class RiskMeter(Flowable):
        def __init__(self, score, label, width):
            super().__init__()
            self.score = max(0, min(100, int(score)))
            self.label = str(label or "unknown").upper()
            self.width = width
            self.height = 25
            self.fill, _ = pill_color(label)

        def draw(self):
            self.canv.setFillColor(colors.HexColor("#E7EDF5"))
            self.canv.roundRect(0, 11, self.width, 7, 3, fill=1, stroke=0)
            self.canv.setFillColor(self.fill)
            self.canv.roundRect(0, 11, self.width * self.score / 100, 7, 3, fill=1, stroke=0)
            self.canv.setFillColor(ink)
            self.canv.setFont("Helvetica-Bold", 7.5)
            self.canv.drawString(0, 0, f"Risk score: {self.score}/100")
            self.canv.setFillColor(self.fill)
            self.canv.drawRightString(self.width, 0, self.label)

    generated_for_header = generated
    output = BytesIO()
    page_width, page_height = A4
    left_margin = 12 * mm
    right_margin = 12 * mm
    top_margin = 31 * mm
    bottom_margin = 14 * mm
    usable_width = page_width - left_margin - right_margin

    def draw_page(canvas, doc):
        canvas.saveState()
        # Dark blue report banner, repeated on continuation pages.
        banner_height = 24 * mm
        canvas.setFillColor(navy)
        canvas.rect(0, page_height - banner_height, page_width, banner_height, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#0D4C8C"))
        canvas.circle(15 * mm, page_height - 12 * mm, 7.5 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(colors.HexColor("#73C5FF"))
        canvas.setLineWidth(1.8)
        # Simple shield-like mark, drawn vectorially.
        path = canvas.beginPath()
        path.moveTo(15 * mm, page_height - 5.8 * mm)
        path.lineTo(19.4 * mm, page_height - 8 * mm)
        path.lineTo(19.0 * mm, page_height - 14.6 * mm)
        path.lineTo(15 * mm, page_height - 18.1 * mm)
        path.lineTo(11 * mm, page_height - 14.6 * mm)
        path.lineTo(10.6 * mm, page_height - 8 * mm)
        path.close()
        canvas.drawPath(path, stroke=1, fill=0)
        canvas.setFillColor(white)
        canvas.setFont("Helvetica-Bold", 16)
        canvas.drawString(27 * mm, page_height - 10.5 * mm, "Phishing Analysis Report")
        canvas.setFillColor(colors.HexColor("#D7E9FC"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(27 * mm, page_height - 16.5 * mm, "Security Threat Detection and Investigation")
        # Metadata at right of header, grounded in this report.
        meta_x = page_width - 72 * mm
        canvas.setStrokeColor(colors.HexColor("#3B6793"))
        canvas.line(meta_x - 3 * mm, page_height - 21 * mm, meta_x - 3 * mm, page_height - 3 * mm)
        canvas.setFillColor(colors.HexColor("#D7E9FC"))
        canvas.setFont("Helvetica", 6.4)
        canvas.drawString(meta_x, page_height - 6.5 * mm, "Report ID")
        canvas.drawString(meta_x, page_height - 10.8 * mm, "Generated")
        canvas.drawString(meta_x, page_height - 15.1 * mm, "Analyst")
        canvas.drawString(meta_x, page_height - 19.4 * mm, "Report version")
        canvas.setFillColor(white)
        canvas.setFont("Helvetica-Bold", 6.5)
        canvas.drawRightString(page_width - 4 * mm, page_height - 6.5 * mm, case_id[:28])
        canvas.setFont("Helvetica", 6.2)
        canvas.drawRightString(page_width - 4 * mm, page_height - 10.8 * mm, generated_for_header)
        canvas.drawRightString(page_width - 4 * mm, page_height - 15.1 * mm, "Automated Analysis System")
        canvas.drawRightString(page_width - 4 * mm, page_height - 19.4 * mm, "1.1")
        # Footer.
        canvas.setStrokeColor(border)
        canvas.setLineWidth(0.5)
        canvas.line(left_margin, 9 * mm, page_width - right_margin, 9 * mm)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(left_margin, 5.5 * mm, "MAILTRACE-X | Evidence-based automated analysis | Attachments are not executed")
        canvas.drawRightString(page_width - right_margin, 5.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def section_header(number, title, width=usable_width):
        number_text = Paragraph(safe(number, ""), styles["SectionNumber"])
        t = Table([[number_text, Paragraph(escape(title), styles["CardTitle"])]], colWidths=[8 * mm, width - 8 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), blue),
            ("TEXTCOLOR", (0, 0), (0, 0), white),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (1, 0), (1, 0), light_blue),
            ("BOX", (0, 0), (-1, -1), 0.5, border),
            ("LEFTPADDING", (0, 0), (0, 0), 2),
            ("RIGHTPADDING", (0, 0), (0, 0), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (1, 0), (1, 0), 7),
        ]))
        return t

    def body_table(rows, col_widths, repeat_rows=0, compact=False):
        t = Table(rows, colWidths=col_widths, repeatRows=repeat_rows, hAlign="LEFT")
        pad = 3.2 if compact else 4.2
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), light_blue if repeat_rows else white),
            ("TEXTCOLOR", (0, 0), (-1, 0), navy),
            ("GRID", (0, 0), (-1, -1), 0.35, border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), pad),
            ("RIGHTPADDING", (0, 0), (-1, -1), pad),
            ("TOPPADDING", (0, 0), (-1, -1), pad),
            ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ]))
        return t

    def add_section(story, number, title, table, gap=7):
        story.append(CondPageBreak(24 * mm))
        story.append(section_header(number, title))
        story.append(table)
        story.append(Spacer(1, gap))

    def card(number, title, content, width):
        heading = section_header(number, title, width=width)
        t = Table([[heading], [content]], colWidths=[width], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.55, border),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (0, 0), 0),
            ("BOTTOMPADDING", (0, 0), (0, 0), 0),
            ("LEFTPADDING", (0, 1), (-1, 1), 5),
            ("RIGHTPADDING", (0, 1), (-1, 1), 5),
            ("TOPPADDING", (0, 1), (-1, 1), 5),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    def make_key_value(rows, width, label_fraction=0.38):
        label_width = width * label_fraction
        prepared = []
        for label, value in rows:
            prepared.append([para(label, "CellBold"), para(value, "Cell")])
        if not prepared:
            prepared = [[para("Status", "CellBold"), para("No data available", "Cell")]]
        t = Table(prepared, colWidths=[label_width, width - label_width], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, border),
            ("BACKGROUND", (0, 0), (0, -1), pale),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3.4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.4),
        ]))
        return t

    def severity_cell(severity):
        fg, bg = pill_color(severity)
        return Paragraph(f'<font color="{fg.hexval()}"><b>{safe(severity, "unknown").upper()}</b></font>', styles["Cell"])

    def status_card(label, value):
        fg, bg = pill_color(value)
        data = [[para(label, "TableHead")], [Paragraph(f'<font color="{fg.hexval()}"><b>{safe(value, "unknown").upper()}</b></font>', styles["Verdict"])]]
        t = Table(data, colWidths=[usable_width / 3 - 4], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg), ("BOX", (0, 0), (-1, -1), 0.5, border),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    # Index enriched entities so only genuine lookup values appear in the report.
    entity_index = {}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("type", "")).lower()
        entity_value = str(entity.get("value", ""))
        if entity_value:
            entity_index[(entity_type, entity_value.lower())] = entity

    risk_score = risk.get("score", 0)
    try:
        risk_score = max(0, min(100, int(risk_score)))
    except (ValueError, TypeError):
        risk_score = 0
    risk_level = str(risk.get("level", "unknown")).lower()
    classification = str(detection.get("classification", "unknown")).lower()
    probability = detection.get("phishing_probability", 0)
    confidence = risk.get("confidence", 0)
    try:
        probability = max(0.0, min(1.0, float(probability)))
    except (ValueError, TypeError):
        probability = 0.0
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (ValueError, TypeError):
        confidence = 0.0

    doc = SimpleDocTemplate(
        output, pagesize=A4,
        leftMargin=left_margin, rightMargin=right_margin,
        topMargin=top_margin, bottomMargin=bottom_margin,
        title=f"MAILTRACE-X Phishing Analysis Report - {case_id}",
        author="MAILTRACE-X Automated Analysis System",
        subject="Evidence-based email phishing investigation",
    )
    story = []
    half = (usable_width - 5 * mm) / 2

    # Section 1: scope / methodology.
    scope_rows = [[para("REPORT SCOPE", "TableHead"), para(
        "This report is generated from the structured evidence extracted from the uploaded .eml file, the detection result, and any enrichment available for this case. Values marked unknown or not checked were not confirmed by the available evidence. Attachments are not executed.", "Scope")]]
    scope = Table(scope_rows, colWidths=[25 * mm, usable_width - 25 * mm])
    scope.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale), ("BOX", (0, 0), (-1, -1), 0.5, border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [section_header(1, "Contents and report scope"), scope, Spacer(1, 7)]

    # Section 2: risk card.
    risk_rows = [
        ("Case ID", case_id),
        ("Risk score", f"{risk_score}/100 ({risk_level.upper()})"),
        ("Classification", classification.upper()),
        ("Phishing probability", f"{probability:.0%}"),
        ("Confidence", f"{confidence:.0%}"),
        ("Detection model", detection.get("model", "Not recorded")),
    ]
    risk_inner_width = half - 10
    risk_kv = make_key_value(risk_rows, risk_inner_width, 0.39)
    risk_inner = Table([[risk_kv], [RiskMeter(risk_score, risk_level, risk_inner_width - 4)]], colWidths=[risk_inner_width], hAlign="LEFT")
    risk_inner.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    risk_card = card(2, "Case summary and risk assessment", risk_inner, half)

    # Section 3: exact email metadata from parser.
    recipients = ", ".join(str(item) for item in (metadata.get("recipients") or [])) or "Not present in message"
    email_rows = [
        ("Sender address", metadata.get("sender") or "Not present in message"),
        ("Email subject", metadata.get("subject") or "Not present in message"),
        ("Date received", metadata.get("date") or "Not present in message"),
        ("Recipient(s)", recipients),
        ("Reply-To", metadata.get("reply_to") or "Not present in message"),
        ("Return-Path", metadata.get("return_path") or "Not present in message"),
        ("Message ID", metadata.get("message_id") or "Not present in message"),
    ]
    email_card = card(3, "Email summary", make_key_value(email_rows, half - 10, 0.34), half)
    top_pair = Table([[risk_card, email_card]], colWidths=[half, half], hAlign="LEFT")
    top_pair.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 2.5), ("LEFTPADDING", (1, 0), (1, 0), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story += [top_pair, Spacer(1, 8)]

    # Section 4: real evidence signals only.
    evidence_rows = [[para("Finding ID", "TableSmallHead"), para("Severity", "TableSmallHead"), para("Category", "TableSmallHead"), para("Finding and recorded details", "TableSmallHead")]]
    for item in signals:
        if not isinstance(item, dict):
            continue
        details = item.get("evidence") or {}
        details_text = "; ".join(f"{key}: {value}" for key, value in details.items() if value not in (None, "", [], {}))
        description = str(item.get("description") or "No description recorded")
        if details_text:
            description += "\nEvidence: " + details_text
        evidence_rows.append([
            para(item.get("signal_id") or "Not assigned", "TableSmall"),
            severity_cell(item.get("severity", "unknown")),
            para(item.get("category") or "Uncategorised", "TableSmall"),
            para(description, "TableSmall"),
        ])
    if len(evidence_rows) == 1:
        evidence_rows.append([para("—", "TableSmall"), para("None recorded", "TableSmall"), para("Current analyzers", "TableSmall"), para("No structured evidence signals were produced for this email.", "TableSmall")])
    evidence_table = body_table(evidence_rows, [23 * mm, 21 * mm, 23 * mm, usable_width - 67 * mm], repeat_rows=1, compact=True)
    add_section(story, 4, "Evidence and security findings", evidence_table)

    # Section 5: reported authentication header values + actual counts.
    auth_rows = [
        [para("Mechanism", "TableHead"), para("Reported result", "TableHead"), para("Interpretation", "TableHead")],
    ]
    for mechanism in ("spf", "dkim", "dmarc"):
        value = str(auth.get(mechanism, "unknown") or "unknown").lower()
        interpretation = {
            "pass": "Header reports a pass",
            "fail": "Header reports a failure",
            "softfail": "Header reports a soft failure",
            "none": "No result reported",
            "neutral": "Header reports a neutral result",
            "temperror": "Temporary evaluation error reported",
            "permerror": "Permanent evaluation error reported",
            "unknown": "No usable result found in parsed headers",
        }.get(value, "Reported header value; not independently validated")
        auth_rows.append([para(mechanism.upper(), "CellBold"), severity_cell(value), para(interpretation, "TableSmall")])
    auth_inner_width = half - 18
    auth_table = body_table(auth_rows, [20 * mm, 24 * mm, auth_inner_width - 44 * mm], repeat_rows=1, compact=True)
    auth_note = Paragraph("<font color='#536782'>Important: these are values parsed from Authentication-Results / Received-SPF headers. MAILTRACE-X does not independently perform DNS or cryptographic validation of SPF, DKIM, or DMARC.</font>", styles["Small"])
    auth_stack = Table([[auth_table], [auth_note]], colWidths=[half - 10])
    auth_stack.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, border), ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    indicator_counts = [
        ("URLs", len(iocs.get("urls") or [])),
        ("Domains", len(iocs.get("domains") or [])),
        ("IP addresses", len(iocs.get("ips") or [])),
        ("Email addresses", len(iocs.get("emails") or [])),
        ("Attachments", len(attachments)),
        ("Related cases", len(related_cases)),
    ]
    counts_table = make_key_value([(label, str(count)) for label, count in indicator_counts], half - 10, 0.64)
    auth_card = card(5, "Email authentication", auth_stack, half)
    counts_card = card("i", "Extracted indicator counts", counts_table, half)
    pair = Table([[auth_card, counts_card]], colWidths=[half, half], hAlign="LEFT")
    pair.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 2.5), ("LEFTPADDING", (1, 0), (1, 0), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story += [pair, Spacer(1, 8)]

    # Section 7: all IOCs actually extracted from this email, enriched only if a real result exists.
    ioc_rows = [[para("Type", "TableSmallHead"), para("Extracted value", "TableSmallHead"), para("Available context", "TableSmallHead")]]
    for kind, key, entity_type in (("URL", "urls", None), ("Domain", "domains", "domain"), ("IP address", "ips", "ip"), ("Email address", "emails", None)):
        for value in (iocs.get(key) or []):
            context = "Extracted from the email; not proof of malicious activity."
            ent = entity_index.get((entity_type, str(value).lower())) if entity_type else None
            if ent:
                details = ent.get("details") or {}
                risk_reasons = ent.get("risk_reasons") or []
                risk_val = ent.get("risk")
                parts = []
                status = details.get("status")
                if status:
                    parts.append(f"Lookup status: {status}")
                if risk_val is not None:
                    parts.append(f"Enrichment risk: {risk_val}/100")
                if risk_reasons:
                    parts.extend(str(x) for x in risk_reasons)
                if entity_type == "ip":
                    rep = details.get("reputation") or {}
                    if rep.get("status"):
                        parts.append(f"IP reputation status: {rep['status']}")
                    if rep.get("status") == "ok":
                        parts.append(f"Abuse confidence: {rep.get('abuse_score', 0)}/100 ({rep.get('total_reports', 0)} reports)")
                context = "; ".join(parts) or context
            elif kind == "Domain" and not ent:
                context = "Extracted from the email; no domain enrichment result is recorded."
            ioc_rows.append([para(kind, "TableSmall"), para(value, "TableSmall"), para(context, "TableSmall")])
    if len(ioc_rows) == 1:
        ioc_rows.append([para("—", "TableSmall"), para("No indicators extracted", "TableSmall"), para("No URL, domain, IP address, or email address was returned by the IOC extractor.", "TableSmall")])
    ioc_table = body_table(ioc_rows, [22 * mm, 65 * mm, usable_width - 87 * mm], repeat_rows=1, compact=True)
    add_section(story, 6, "Indicators of compromise (IOCs)", ioc_table)

    # Section 8: attachment hashes and live hash reputation lookup result, without false-safe claims.
    attachment_rows = [[para("Filename", "TableSmallHead"), para("MIME type / size", "TableSmallHead"), para("SHA-256", "TableSmallHead"), para("Hash reputation result", "TableSmallHead")]]
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue
        sha = str(attachment.get("sha256", ""))
        ent = entity_index.get(("hash", sha.lower())) if sha else None
        details = (ent or {}).get("details") or {}
        rep = details.get("reputation") or {}
        if rep.get("status") == "ok" and rep.get("found") is True:
            reputation = "MATCH: listed malware sample"
            if rep.get("signature"):
                reputation += f"; signature: {rep['signature']}"
            if rep.get("tags"):
                reputation += "; tags: " + ", ".join(str(x) for x in rep.get("tags", [])[:5])
        elif rep.get("status") == "ok" and rep.get("found") is False:
            reputation = "No MalwareBazaar listing found; this does not prove the file is safe."
        elif rep.get("status") == "no_api_key":
            reputation = "Not checked: MalwareBazaar API key is not configured."
        elif rep.get("status"):
            reputation = f"Lookup not confirmed (status: {rep.get('status')})."
        else:
            reputation = "No hash reputation result recorded."
        attachment_rows.append([
            para(attachment.get("filename", "unnamed attachment"), "TableSmall"),
            para(f"{attachment.get('mime_type', 'unknown')}\n{attachment.get('size_bytes', 'unknown')} bytes", "TableSmall"),
            para(sha or "Not recorded", "TableSmall"),
            para(reputation, "TableSmall"),
        ])
    if len(attachment_rows) == 1:
        attachment_rows.append([para("No attachments found", "TableSmall"), para("—", "TableSmall"), para("—", "TableSmall"), para("No attachment metadata was extracted from this message.", "TableSmall")])
    attachment_table = body_table(attachment_rows, [37 * mm, 32 * mm, 57 * mm, usable_width - 126 * mm], repeat_rows=1, compact=True)
    add_section(story, 7, "Attachment findings", attachment_table)
    note = Table([[para("INFO", "CellBold"), para("Attachments are hashed and may be checked against configured reputation sources. Files are not executed. A hash absent from a reputation database must not be labelled benign solely because no match was found.", "Small")]], colWidths=[14 * mm, usable_width - 14 * mm])
    note.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_blue), ("BOX", (0, 0), (-1, -1), 0.35, border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story += [note, Spacer(1, 8)]

    # Section 9: related cases and graph connections. Only relationships recorded in this case are shown.
    relation_rows = [[para("Related case ID", "TableSmallHead"), para("Shared indicator", "TableSmallHead"), para("All shared indicators", "TableSmallHead"), para("Confidence", "TableSmallHead")]]
    for rel in related_cases:
        if not isinstance(rel, dict):
            continue
        shared = rel.get("shared") or "Not recorded"
        all_shared = rel.get("all_shared") or [shared]
        try:
            conf = max(0, min(1, float(rel.get("confidence", 0))))
        except (TypeError, ValueError):
            conf = 0
        relation_rows.append([
            para(rel.get("case_id", "Unknown"), "TableSmall"),
            para(shared, "TableSmall"),
            para(", ".join(map(str, all_shared)), "TableSmall"),
            para(f"{conf:.0%}", "TableSmall"),
        ])
    if len(relation_rows) == 1:
        relation_rows.append([para("—", "TableSmall"), para("No related cases identified", "TableSmall"), para("No shared case indicators recorded by the correlation graph.", "TableSmall"), para("—", "TableSmall")])
    related_table = body_table(relation_rows, [28 * mm, 42 * mm, usable_width - 92 * mm, 22 * mm], repeat_rows=1, compact=True)
    story.append(CondPageBreak(32 * mm))
    story.append(KeepTogether([section_header(8, "Threat relationships"), related_table]))
    if graph_relationships:
        story.append(Spacer(1, 4))
        story.append(Paragraph("Recorded graph relationships", styles["TableHead"]))
        graph_rows = [[para("Source", "TableSmallHead"), para("Relationship", "TableSmallHead"), para("Target", "TableSmallHead")]]
        for rel in graph_relationships:
            if not isinstance(rel, dict):
                continue
            graph_rows.append([para(rel.get("source", "—"), "TableSmall"), para(rel.get("relation", "—"), "TableSmall"), para(rel.get("target", "—"), "TableSmall")])
        if len(graph_rows) > 1:
            story.append(body_table(graph_rows, [usable_width * 0.39, usable_width * 0.22, usable_width * 0.39], repeat_rows=1, compact=True))
    story.append(Spacer(1, 8))

    # Section 10: detection explanation includes only model-provided values.
    story.append(CondPageBreak(30 * mm))
    story.append(section_header(9, "Detection explanation"))
    model_text = para(f"Model: {detection.get('model', 'Not recorded')} | Classification: {classification.upper()} | Phishing probability: {probability:.0%}", "Body")
    story.append(model_text)
    terms = detection.get("term_contributions") or {}
    term_rows = [[para("Feature / term", "TableSmallHead"), para("Contribution", "TableSmallHead"), para("Direction", "TableSmallHead")]]
    try:
        sorted_terms = sorted(terms.items(), key=lambda kv: abs(float(kv[1])), reverse=True)
    except (AttributeError, TypeError, ValueError):
        sorted_terms = []
    for term, value in sorted_terms[:20]:
        try:
            weight = float(value)
        except (ValueError, TypeError):
            continue
        direction = "Toward phishing" if weight > 0 else "Against phishing" if weight < 0 else "Neutral"
        term_rows.append([para(term, "TableSmall"), para(f"{weight:+.4f}", "TableSmall"), para(direction, "TableSmall")])
    if len(term_rows) == 1:
        term_rows.append([para("No term contributions recorded", "TableSmall"), para("—", "TableSmall"), para("The active detector did not return per-term contributions.", "TableSmall")])
    term_table = body_table(term_rows, [usable_width * 0.47, usable_width * 0.20, usable_width * 0.33], repeat_rows=1, compact=True)
    story.append(term_table)

    features = detection.get("features") or {}
    if features:
        story.append(Spacer(1, 4))
        story.append(Paragraph("Model input features", styles["TableHead"]))
        feature_rows = [[para("Feature", "TableSmallHead"), para("Recorded value", "TableSmallHead")]]
        for key, value in sorted(features.items()):
            feature_rows.append([para(key, "TableSmall"), para(value, "TableSmall")])
        story.append(body_table(feature_rows, [usable_width * 0.63, usable_width * 0.37], repeat_rows=1, compact=True))

    detection_reasons = detection.get("reasons") or []
    risk_reasons = risk.get("reasons") or []
    if detection_reasons or risk_reasons:
        story.append(Spacer(1, 4))
        reason_text = []
        if detection_reasons:
            reason_text.append("<b>Detector reasons:</b> " + "; ".join(safe(x) for x in detection_reasons))
        if risk_reasons:
            reason_text.append("<b>Risk reasons:</b> " + "; ".join(safe(x) for x in risk_reasons))
        story.append(Paragraph("<br/>".join(reason_text), styles["Small"]))
    story.append(Spacer(1, 8))

    # Dynamic bottom-line summary; do not claim more than returned model data says.
    count_signals = len(signals)
    count_urls = len(iocs.get("urls") or [])
    count_domains = len(iocs.get("domains") or [])
    count_ips = len(iocs.get("ips") or [])
    count_attachments = len(attachments)
    summary = (
        f"The detector classified this message as {classification.upper()} with a phishing probability of {probability:.0%}. "
        f"The composite risk assessment is {risk_score}/100 ({risk_level.upper()}) with {confidence:.0%} confidence. "
        f"The parser returned {count_signals} structured finding(s), {count_urls} URL(s), {count_domains} domain(s), "
        f"{count_ips} IP address(es), and {count_attachments} attachment(s). These counts describe extracted evidence; "
        "they do not, by themselves, prove that every indicator or attachment is malicious."
    )
    recommendation = _recommendation(classification, risk_level)
    overall_color = pale_red if risk_level in {"critical", "high"} else pale_amber if risk_level == "medium" else pale_green if risk_level == "low" else pale
    overall_fg, _ = pill_color(risk_level)
    conclusion = Table([
        [Paragraph("ANALYSIS SUMMARY", styles["CardTitle"]), Paragraph(f'<font color="{overall_fg.hexval()}"><b>OVERALL ASSESSMENT: {escape(risk_level.upper())} RISK</b></font>', styles["CardTitle"])],
        [para(summary, "Body"), para(recommendation, "Body")],
    ], colWidths=[usable_width * 0.61, usable_width * 0.39])
    conclusion.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), overall_color), ("BOX", (0, 0), (-1, -1), 0.7, border),
        ("LINEBEFORE", (1, 0), (1, -1), 0.7, overall_fg), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [conclusion, Spacer(1, 4)]

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return output.getvalue()
