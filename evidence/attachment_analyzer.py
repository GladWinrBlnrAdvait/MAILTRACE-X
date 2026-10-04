import hashlib
from typing import List

from evidence.models import AttachmentEvidence


def analyze_attachments(message) -> List[AttachmentEvidence]:
    """
    Extract attachment metadata and calculate SHA-256 hashes.

    The attachments are NOT executed or opened.
    """

    attachments = []

    for part in message.walk():

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

        attachment = AttachmentEvidence(
            filename=filename or "unnamed_attachment",
            mime_type=part.get_content_type(),
            size_bytes=len(payload),
            sha256=sha256_hash
        )

        attachments.append(attachment)

    return attachments