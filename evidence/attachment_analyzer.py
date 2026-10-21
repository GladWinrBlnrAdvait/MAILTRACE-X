import hashlib
from typing import List

from evidence.attachment_static import analyze_attachment_content
from evidence.models import AttachmentEvidence


def analyze_attachments(message, parts=None) -> List[AttachmentEvidence]:
    """
    Extract attachment metadata, calculate SHA-256 hashes and run
    static content analysis (see evidence/attachment_static.py).

    The attachments are NOT executed or opened.
    """

    attachments = []

    for part in (parts if parts is not None else message.walk()):

        disposition = part.get_content_disposition()
        filename = part.get_filename()

        # Skip parts that are not attachments
        if disposition != "attachment" and not filename:
            continue

        # Decode attachment content
        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        # Calculate SHA-256 fingerprint
        sha256_hash = hashlib.sha256(payload).hexdigest()

        attachment_name = filename or "unnamed_attachment"

        # Static analysis only: bytes are inspected in memory, never executed
        detected_type, signals = analyze_attachment_content(
            attachment_name,
            payload
        )

        attachment = AttachmentEvidence(
            filename=attachment_name,
            mime_type=part.get_content_type(),
            size_bytes=len(payload),
            sha256=sha256_hash,
            detected_type=detected_type,
            signals=signals
        )

        attachments.append(attachment)

    return attachments