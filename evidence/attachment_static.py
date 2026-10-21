"""
Static (non-executing) attachment analysis.

Nothing in this module runs, opens in an application, or extracts to disk
any attachment. It only inspects bytes in memory.

Signals produced (all use the standard MAILTRACE-X signal format):

    ATT-001  File content does not match its extension
    ATT-002  Double extension / right-to-left-override filename trick
    ATT-003  High-risk file type (executable, script, disk image, ...)
    ATT-004  Office document contains VBA macros
    ATT-005  Macro runs automatically when the document is opened
    ATT-006  PDF contains JavaScript
    ATT-007  PDF has an automatic action (/OpenAction or /AA)
    ATT-008  PDF has a /Launch action
    ATT-009  Archive contains executable or script files
    ATT-010  Archive is password-protected (contents cannot be inspected)

To avoid piling several signals onto the same fact, ATT-003 is only
raised when neither ATT-001 nor ATT-002 already flagged the file.

Known limitations (state these in the paper):
  * PDF checks look for name tokens, in the raw file and in Flate-decoded
    streams. Heavily obfuscated or encrypted PDFs can still evade them.
  * Macro analysis depends on `oletools`. Without it, only a coarse
    OOXML check (presence of vbaProject.bin) is available.
  * Only ZIP archives are listed. RAR, 7z, etc. are identified but not opened.
"""

import io
import re
import warnings
import zipfile
import zlib
from typing import Dict, List, Optional, Tuple

MAX_ANALYSIS_BYTES = 25 * 1024 * 1024   # skip deep inspection above this
MAX_ZIP_ENTRIES = 1000
MAX_PDF_STREAMS = 200
MAX_DECOMPRESSED_STREAM = 2 * 1024 * 1024

# ---------------------------------------------------------------------------
# File-type tables
# ---------------------------------------------------------------------------

HIGH_RISK_EXTENSIONS = {
    "exe", "scr", "com", "pif", "msi", "msp", "dll", "cpl",
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "jar", "lnk", "reg",
    "iso", "img", "vhd", "vhdx",
}

DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
    "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "zip",
}

# extension -> set of detected types that are consistent with it
EXPECTED_TYPES: Dict[str, set] = {
    "pdf": {"pdf"},
    "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"},
    "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"},
    "docm": {"ooxml"}, "xlsm": {"ooxml"}, "pptm": {"ooxml"},
    "zip": {"zip", "ooxml", "jar"},
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "rtf": {"rtf"},
    "txt": {"text"}, "csv": {"text"},
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"},
}

EXECUTABLE_TYPES = {"pe", "elf"}

_SIGNATURES = [
    (b"%PDF-", "pdf"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"{\\rtf", "rtf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
]

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_extension(filename: str) -> str:
    """Final extension, lower-case, without the dot ('' if none)."""
    name = (filename or "").strip().rstrip(". ")
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[1].lower()


def _zip_names(payload: bytes) -> Optional[List[str]]:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            return [i.filename for i in archive.infolist()[:MAX_ZIP_ENTRIES]]
    except Exception:
        return None


def detect_file_type(payload: bytes) -> Optional[str]:
    """
    Identify content by magic bytes. Returns a short type name, 'text',
    or None when the content cannot be identified.
    """
    if not payload:
        return None

    if payload.startswith(_ZIP_MAGICS):
        names = _zip_names(payload)
        if names is None:
            return "zip"
        if "[Content_Types].xml" in names:
            return "ooxml"
        if "META-INF/MANIFEST.MF" in names:
            return "jar"
        return "zip"

    for magic, name in _SIGNATURES:
        if payload.startswith(magic):
            return name

    sample = payload[:4096]
    if b"\x00" not in sample:
        return "text"
    return None


def _signal(signal_id: str, severity: str, description: str,
            filename: str, **evidence) -> dict:
    return {
        "signal_id": signal_id,
        "category": "attachment",
        "severity": severity,
        "description": description,
        "evidence": {"filename": filename, **evidence},
    }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_filename(filename: str, extension: str, detected: Optional[str],
                    signals: List[dict]) -> None:
    """ATT-001, ATT-002, ATT-003 (filename- and type-based)."""
    lowered = (filename or "").lower().strip().rstrip(". ")
    parts = lowered.split(".")

    double_extension = (
        len(parts) >= 3
        and parts[-1] in HIGH_RISK_EXTENSIONS
        and parts[-2] in DOCUMENT_EXTENSIONS
    )
    rlo = "\u202e" in (filename or "")

    flagged = False

    if double_extension or rlo:
        flagged = True
        reason = ("right-to-left override character in filename"
                  if rlo and not double_extension
                  else "document extension followed by executable extension")
        signals.append(_signal(
            "ATT-002", "high",
            "Attachment filename disguises its real file type",
            filename, reason=reason, final_extension="." + extension,
        ))

    expected = EXPECTED_TYPES.get(extension)
    if expected and detected and detected not in expected and not flagged:
        severity = "high" if detected in EXECUTABLE_TYPES else "medium"
        flagged = True
        signals.append(_signal(
            "ATT-001", severity,
            "Attachment content does not match its file extension",
            filename, extension="." + extension, detected_type=detected,
        ))

    if not flagged and (extension in HIGH_RISK_EXTENSIONS
                        or detected in EXECUTABLE_TYPES):
        signals.append(_signal(
            "ATT-003", "high",
            "Attachment is a high-risk file type",
            filename, extension="." + extension if extension else "",
            detected_type=detected,
        ))


def _summarize_macro_findings(results) -> Tuple[List[str], List[str]]:
    """Split oletools analyze_macros() output into (autoexec, suspicious)."""
    autoexec = sorted({kw for kind, kw, _ in results if kind == "AutoExec"})
    suspicious = sorted({kw for kind, kw, _ in results if kind == "Suspicious"})
    return autoexec, suspicious


def _check_macros(filename: str, payload: bytes, detected: Optional[str],
                  signals: List[dict]) -> None:
    """ATT-004, ATT-005."""
    if detected not in {"ole", "ooxml"}:
        return

    has_macros = False
    autoexec: List[str] = []
    suspicious: List[str] = []
    method = "oletools"

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # oletools is noisy on import
            from oletools.olevba import VBA_Parser  # lazy: optional dependency
        parser = VBA_Parser(filename or "attachment", data=payload)
        try:
            if parser.detect_vba_macros():
                has_macros = True
                autoexec, suspicious = _summarize_macro_findings(
                    parser.analyze_macros()
                )
        finally:
            parser.close()
    except ImportError:
        method = "heuristic"
        names = _zip_names(payload) if detected == "ooxml" else None
        has_macros = bool(names and any(
            n.lower().endswith("vbaproject.bin") for n in names
        ))
    except Exception:
        return  # unreadable/corrupt document: no macro verdict

    if not has_macros:
        return

    signals.append(_signal(
        "ATT-004", "high", "Office document contains VBA macros",
        filename, analysis=method, suspicious_keywords=suspicious,
    ))

    if autoexec:
        signals.append(_signal(
            "ATT-005", "high",
            "Macro is set to run automatically when the document is opened",
            filename, autoexec_triggers=autoexec,
            suspicious_keywords=suspicious,
        ))


_PDF_NAME_ESCAPE = re.compile(r"#([0-9A-Fa-f]{2})")
MAX_PDF_SCAN_STEPS = 2000


def _pdf_streams(payload: bytes):
    """
    Yield the raw bytes of each stream...endstream block.

    Uses bytes.find with a hard step limit instead of a regex, so a hostile
    file full of "stream" markers cannot cause quadratic-time scanning.
    """
    position = 0
    found = 0
    for _ in range(MAX_PDF_SCAN_STEPS):
        if found >= MAX_PDF_STREAMS:
            return
        marker = payload.find(b"stream", position)
        if marker == -1:
            return
        position = marker + 6
        if payload[max(0, marker - 3):marker] == b"end":
            continue                      # that was an "endstream"
        start = position
        if payload[start:start + 2] == b"\r\n":
            start += 2
        elif payload[start:start + 1] == b"\n":
            start += 1
        end = payload.find(b"endstream", start)
        if end == -1:
            return
        found += 1
        position = end + 9
        yield payload[start:end]


def _pdf_scan_text(payload: bytes) -> str:
    """Raw PDF text plus the contents of Flate-compressed streams."""
    chunks = [payload]
    for stream in _pdf_streams(payload):
        try:
            decompressor = zlib.decompressobj()
            chunks.append(decompressor.decompress(
                stream, MAX_DECOMPRESSED_STREAM
            ))
        except Exception:
            continue
    text = b"\n".join(chunks).decode("latin-1")
    # Undo name obfuscation such as /J#61vaScript
    return _PDF_NAME_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _pdf_has(text: str, name: str) -> bool:
    return re.search(rf"/{name}(?![A-Za-z0-9])", text) is not None


def _check_pdf(filename: str, payload: bytes, detected: Optional[str],
               signals: List[dict]) -> None:
    """ATT-006, ATT-007, ATT-008."""
    if detected != "pdf":
        return
    try:
        text = _pdf_scan_text(payload)
    except Exception:
        return

    if _pdf_has(text, "JavaScript") or _pdf_has(text, "JS"):
        signals.append(_signal(
            "ATT-006", "high", "PDF contains JavaScript", filename,
        ))

    auto = [n for n in ("OpenAction", "AA") if _pdf_has(text, n)]
    if auto:
        signals.append(_signal(
            "ATT-007", "medium",
            "PDF defines an action that runs automatically on open",
            filename, actions=["/" + n for n in auto],
        ))

    if _pdf_has(text, "Launch"):
        signals.append(_signal(
            "ATT-008", "high", "PDF contains a /Launch action", filename,
        ))


def _check_archive(filename: str, payload: bytes, detected: Optional[str],
                   signals: List[dict]) -> None:
    """ATT-009, ATT-010 (ZIP only; the archive is listed, never extracted)."""
    if detected != "zip":
        return
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()[:MAX_ZIP_ENTRIES]
    except Exception:
        return

    risky = [i.filename for i in infos
             if get_extension(i.filename) in HIGH_RISK_EXTENSIONS]
    if risky:
        signals.append(_signal(
            "ATT-009", "high",
            "Archive contains executable or script files",
            filename, entries=risky[:10],
        ))

    if any(i.flag_bits & 0x1 for i in infos):
        signals.append(_signal(
            "ATT-010", "medium",
            "Archive is password-protected, so its contents cannot be inspected",
            filename, entry_count=len(infos),
        ))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_attachment_content(filename: str,
                               payload: bytes) -> Tuple[Optional[str], List[dict]]:
    """
    Statically analyze one attachment.

    Returns (detected_type, signals). Never raises: a failure in one check
    only means that check produces no signal.
    """
    signals: List[dict] = []
    payload = payload or b""

    try:
        detected = detect_file_type(payload)
    except Exception:
        detected = None

    extension = get_extension(filename)

    try:
        _check_filename(filename, extension, detected, signals)
    except Exception:
        pass

    if len(payload) <= MAX_ANALYSIS_BYTES:
        for check in (_check_macros, _check_pdf, _check_archive):
            try:
                check(filename, payload, detected, signals)
            except Exception:
                continue

    return detected, signals
