from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EmailMetadata:
    sender: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None


@dataclass
class EmailBody:
    text: str = ""
    html: str = ""


@dataclass
class IOCCollection:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)


@dataclass
class AttachmentEvidence:
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    # Added by static analysis (additive; older callers can ignore these).
    detected_type: Optional[str] = None
    signals: List[dict] = field(default_factory=list)
    # Optional hash-reputation / sandbox summary (see evidence/sandbox.py).
    sandbox: Optional[dict] = None


@dataclass
class AuthenticationEvidence:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


@dataclass
class EmailEvidence:
    case_id: str

    metadata: EmailMetadata = field(default_factory=EmailMetadata)

    received_headers: List[str] = field(default_factory=list)

    body: EmailBody = field(default_factory=EmailBody)

    iocs: IOCCollection = field(default_factory=IOCCollection)

    attachments: List[AttachmentEvidence] = field(default_factory=list)

    authentication: AuthenticationEvidence = field(
        default_factory=AuthenticationEvidence
    )
    evidence_signals: List[dict] = field(default_factory=list)

    # Received-header timeline, oldest hop first (see evidence/received_chain.py)
    received_hops: List[dict] = field(default_factory=list)
    origin_ip: Optional[str] = None