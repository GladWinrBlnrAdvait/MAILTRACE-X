from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

from evidence.models import EmailEvidence, EmailMetadata, EmailBody
from evidence.ioc_extractor import extract_iocs
from evidence.attachment_analyzer import analyze_attachments
from evidence.header_analyzer import analyze_headers
from evidence.authentication import analyze_authentication
from evidence.signal_engine import generate_authentication_signals


def parse_email(file_path: str, case_id: str) -> EmailEvidence:
    """
    Parse an .eml file and convert it into structured EmailEvidence.
    """

    # -------------------------------------------------
    # 1. Read and parse raw email
    # -------------------------------------------------

    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    # -------------------------------------------------
    # 2. Extract metadata
    # -------------------------------------------------

    sender = message.get("From")

    recipient_headers = message.get_all("To", [])

    recipients = [
        address
        for _, address in getaddresses(recipient_headers)
    ]

    metadata = EmailMetadata(
        sender=sender,
        recipients=recipients,
        reply_to=message.get("Reply-To"),
        subject=message.get("Subject"),
        date=message.get("Date"),
        message_id=message.get("Message-ID"),
        return_path=message.get("Return-Path"),
    )

    # -------------------------------------------------
    # 3. Extract Received headers
    # -------------------------------------------------

    received_headers = message.get_all("Received", [])

    # -------------------------------------------------
    # 4. Extract body
    # -------------------------------------------------

    text_body = ""
    html_body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            # Attachments are analyzed separately
            if disposition == "attachment":
                continue

            if content_type == "text/plain":

                try:
                    text_body += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":

                try:
                    html_body += part.get_content()
                except Exception:
                    pass

    else:

        content_type = message.get_content_type()

        try:
            content = message.get_content()
        except Exception:
            content = ""

        if content_type == "text/plain":
            text_body = content

        elif content_type == "text/html":
            html_body = content

    body = EmailBody(
        text=text_body,
        html=html_body
    )

    # -------------------------------------------------
    # 5. IOC Extraction
    # -------------------------------------------------

    ioc_source = "\n".join([
        sender or "",
        metadata.reply_to or "",
        metadata.subject or "",
        metadata.return_path or "",
        "\n".join(received_headers),
        text_body,
        html_body
    ])

    iocs = extract_iocs(ioc_source)

    # -------------------------------------------------
    # 6. Attachment Analysis
    # -------------------------------------------------

    attachments = analyze_attachments(message)

    # -------------------------------------------------
    # 7. Authentication Analysis
    # -------------------------------------------------

    authentication = analyze_authentication(message)

    # -------------------------------------------------
    # 8. Header Forensics
    # -------------------------------------------------

    header_signals = analyze_headers(metadata)

    # -------------------------------------------------
    # 9. Authentication Signals
    # -------------------------------------------------

    authentication_signals = generate_authentication_signals(
        authentication
    )

    evidence_signals = (
        header_signals
        + authentication_signals
    )

    # -------------------------------------------------
    # 10. Build final EmailEvidence object
    # -------------------------------------------------

    evidence = EmailEvidence(
        case_id=case_id,
        metadata=metadata,
        received_headers=received_headers,
        body=body,
        iocs=iocs,
        attachments=attachments,
        authentication=authentication,
        evidence_signals=evidence_signals
    )

    return evidence