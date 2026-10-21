"""
Generate the MAILTRACE-X demonstration email corpus.

Everything here is SAFE and synthetic:
  * Domains use RFC 2606 reserved names (example.com/.net/.org).
  * IPs use RFC 5737 documentation ranges.
  * "Malicious" attachments are harmless stand-ins: a text file that merely
    starts with the 'MZ' bytes, PDFs whose JavaScript is only an alert box,
    and (optionally) an .xlsm carrying XlsxWriter's benign example macro.

Usage (from the repository root):
    python samples/generate_corpus.py
    python samples/generate_corpus.py --vba-bin path/to/vbaProject.bin
    python samples/generate_corpus.py --only phishing_brand_spoof

The macro sample needs `pip install XlsxWriter` and a vbaProject.bin
(the benign one from XlsxWriter's examples folder works). Without it the
macro email is skipped.
"""

import argparse
import io
import os
from email.message import EmailMessage

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Safe attachment builders
# ---------------------------------------------------------------------------

def fake_exe() -> bytes:
    """Starts with 'MZ' so it is *identified* as a PE file, but is plain text."""
    return b"MZ" + b" MAILTRACE-X harmless test stub. This is NOT executable."


def build_pdf(catalog_extra: str, extra_objects: str = "") -> bytes:
    objects = [
        f"<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]
    if extra_objects:
        objects.append(extra_objects)

    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return out


def pdf_with_javascript() -> bytes:
    return build_pdf(
        "/OpenAction 4 0 R",
        "<< /S /JavaScript /JS (app.alert\\('MAILTRACE-X test only'\\);) >>",
    )


def pdf_with_openaction_only() -> bytes:
    return build_pdf("/OpenAction << /S /GoTo /D [3 0 R /Fit] >>")


def macro_xlsm(vba_bin: str) -> bytes:
    import xlsxwriter
    buffer = io.BytesIO()
    workbook = xlsxwriter.Workbook(buffer, {"in_memory": True})
    sheet = workbook.add_worksheet()
    sheet.write("A1", "Q3 payment schedule")
    workbook.add_vba_project(vba_bin)
    workbook.close()
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Message builder
# ---------------------------------------------------------------------------

def build_email(*, sender, to, subject, date, message_id, body,
                reply_to=None, return_path=None, auth=None,
                received=None, attachment=None):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = date
    msg["Message-ID"] = message_id
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    if auth:
        msg["Authentication-Results"] = auth
    for hop in received or []:
        msg["Received"] = hop
    msg.set_content(body)
    if attachment:
        name, mime, data = attachment
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype,
                           filename=name)
    return msg


ONLY = None   # set from --only; MIME boundaries are random, so regenerating
              # a single file avoids rewriting the others


def write(name: str, msg: EmailMessage) -> None:
    if ONLY and name != ONLY + ".eml":
        return
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as handle:
        handle.write(bytes(msg))
    print("wrote", path)


def build_all(vba_bin=None):
    # 6. Brand spoof with forged headers, defanged link and IPv6 hop ---------
    write("phishing_brand_spoof.eml", build_email(
        sender='"support@paypal.com" <service@paypa1-secure.example.org>',
        to="advait@example.net",
        subject="PayPal Support: your account is limited",
        date="Sat, 17 Oct 2026 10:00:00 +0530",
        message_id="<9f1c2@mailer.example.net>",
        reply_to="service@paypa1-secure.example.org",
        return_path="<bounce@paypa1-secure.example.org>",
        auth="mx.example.net; spf=fail smtp.mailfrom=paypa1-secure.example.org; "
             "dkim=none; dmarc=fail header.from=paypa1-secure.example.org",
        # newest first; the oldest hop (last) carries a LATER timestamp than
        # the hop above it, so the chain is out of order
        received=[
            "from relay2.example.org (relay2.example.org [198.51.100.60]) "
            "by mx.example.net with ESMTPS; Sat, 17 Oct 2026 09:40:00 +0530",
            "from app.example.org (unknown [IPv6:2001:db8::25]) "
            "by relay2.example.org with SMTP; Sat, 17 Oct 2026 10:00:05 +0530",
            "from [10.0.0.7] (helo=localhost) by app.example.org "
            "with ESMTP; Sat, 17 Oct 2026 10:00:00 +0530",
        ],
        body="Your account is limited. Verify now: "
             "hxxps://paypa1-secure[.]example[.]org/verify\n"
             "Questions? helpdesk[@]paypa1-secure[.]example[.]org\n",
    ))


    # 1. Benign newsletter ---------------------------------------------------
    write("benign_newsletter.eml", build_email(
        sender='"Example News" <news@example.com>',
        to="advait@example.net",
        subject="Your weekly digest",
        date="Mon, 12 Oct 2026 09:00:00 +0530",
        message_id="<digest-1012@example.com>",
        reply_to="news@example.com",
        return_path="<bounce@example.com>",
        auth="mx.example.net; spf=pass smtp.mailfrom=example.com; "
             "dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
        received=["from mail.example.com (mail.example.com [192.0.2.10]) "
                  "by mx.example.net with ESMTPS; Mon, 12 Oct 2026 09:00:05 +0530"],
        body="Hi,\n\nHere is your weekly digest. Read more at "
             "https://www.example.com/digest/week-41\n\nThe Example News team\n",
    ))

    # 2. Phishing with a macro-enabled workbook ------------------------------
    if vba_bin and os.path.exists(vba_bin):
        write("phishing_macro_invoice.eml", build_email(
            sender='"Finance Desk" <finance@invoices-portal.example.net>',
            to="advait@example.net",
            subject="Payment schedule - action required",
            date="Tue, 13 Oct 2026 11:20:00 +0530",
            message_id="<sched-7731@invoices-portal.example.net>",
            reply_to="payments@secure-remit.example.org",
            return_path="<bounce@mailer.example.org>",
            auth="mx.example.net; spf=fail smtp.mailfrom=invoices-portal.example.net; "
                 "dkim=none; dmarc=fail header.from=invoices-portal.example.net",
            received=["from relay.example.org (relay.example.org [198.51.100.23]) "
                      "by mx.example.net with SMTP; Tue, 13 Oct 2026 11:20:08 +0530"],
            body="Please enable content in the attached workbook to review "
                 "the payment schedule.\n"
                 "Portal: https://invoices-portal.example.net/schedule\n",
            attachment=("Payment_Schedule_Q3.xlsm",
                        "application/vnd.ms-excel.sheet.macroEnabled.12",
                        macro_xlsm(vba_bin)),
        ))
    else:
        if not ONLY:
            print("skipped phishing_macro_invoice.eml (no --vba-bin given)")

    # 3. Phishing with a JavaScript PDF -------------------------------------
    write("phishing_pdf_javascript.eml", build_email(
        sender='"IT Helpdesk" <helpdesk@it-support-desk.example.net>',
        to="advait@example.net",
        subject="Mailbox quota exceeded - open attached form",
        date="Wed, 14 Oct 2026 08:45:00 +0530",
        message_id="<quota-5521@it-support-desk.example.net>",
        reply_to="restore@mailbox-fix.example.org",
        return_path="<bounce@it-support-desk.example.net>",
        auth="mx.example.net; spf=softfail smtp.mailfrom=it-support-desk.example.net; "
             "dkim=fail; dmarc=fail header.from=it-support-desk.example.net",
        received=["from smtp.example.org (smtp.example.org [203.0.113.45]) "
                  "by mx.example.net with SMTP; Wed, 14 Oct 2026 08:45:11 +0530"],
        body="Your mailbox is full. Open the attached form to keep your account.\n"
             "https://mailbox-fix.example.org/restore\n",
        attachment=("Mailbox_Form.pdf", "application/pdf", pdf_with_javascript()),
    ))

    # 4 + 5. Related campaign: two emails sharing billing-update.example.org -
    write("campaign_a_double_extension.eml", build_email(
        sender='"Accounts Payable" <billing@billing-update.example.org>',
        to="advait@example.net",
        subject="Invoice 20931 overdue",
        date="Thu, 15 Oct 2026 10:05:00 +0530",
        message_id="<inv-20931@billing-update.example.org>",
        reply_to="payments@collect-pay.example.net",
        return_path="<bounce@mailer.example.net>",
        auth="mx.example.net; spf=fail smtp.mailfrom=billing-update.example.org; "
             "dkim=none; dmarc=fail header.from=billing-update.example.org",
        received=["from relay.example.net (relay.example.net [198.51.100.77]) "
                  "by mx.example.net with SMTP; Thu, 15 Oct 2026 10:05:09 +0530"],
        body="Invoice 20931 is overdue. Pay now: "
             "https://billing-update.example.org/pay/INV-20931\n"
             "Invoice attached.\n",
        attachment=("Invoice_20931.pdf.exe", "application/octet-stream",
                    fake_exe()),
    ))

    write("campaign_b_followup.eml", build_email(
        sender='"Collections" <ar@accounts-desk.example.org>',
        to="advait@example.net",
        subject="FINAL NOTICE - Invoice 20931",
        date="Fri, 16 Oct 2026 09:30:00 +0530",
        message_id="<final-20931@accounts-desk.example.org>",
        reply_to="ar@accounts-desk.example.org",
        return_path="<bounce@accounts-desk.example.org>",
        auth="mx.example.net; spf=fail smtp.mailfrom=accounts-desk.example.org; "
             "dkim=fail; dmarc=fail header.from=accounts-desk.example.org",
        received=["from smtp.example.com (smtp.example.com [203.0.113.99]) "
                  "by mx.example.net with SMTP; Fri, 16 Oct 2026 09:30:12 +0530"],
        body="Final notice for invoice 20931. Settle immediately at "
             "https://billing-update.example.org/final/INV-20931\n",
        attachment=("Statement.pdf", "application/pdf", pdf_with_openaction_only()),
    ))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--vba-bin", help="path to a benign vbaProject.bin")
    parser.add_argument("--only", help="generate just one file (name without .eml)")
    args = parser.parse_args()
    ONLY = args.only
    build_all(args.vba_bin)
