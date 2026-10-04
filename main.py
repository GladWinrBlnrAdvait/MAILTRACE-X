from dataclasses import asdict
import json
import sys
from pathlib import Path

from evidence.email_parser import parse_email


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <email.eml>")
        return

    file_path = sys.argv[1]

    if not Path(file_path).exists():
        print(f"[ERROR] File not found: {file_path}")
        return

    if not file_path.lower().endswith(".eml"):
        print("[ERROR] Input must be an .eml file.")
        return

    evidence = parse_email(
        file_path,
        case_id="CASE-001"
    )

    print("\n" + "=" * 60)
    print("MAILTRACE-X — EMAIL FORENSIC ANALYSIS")
    print("=" * 60)

    print(f"\nCase ID     : {evidence.case_id}")
    print(f"From        : {evidence.metadata.sender}")
    print(f"To          : {', '.join(evidence.metadata.recipients)}")
    print(f"Subject     : {evidence.metadata.subject}")
    print(f"Reply-To    : {evidence.metadata.reply_to}")

    print("\n--- AUTHENTICATION EVIDENCE ---")
    print(f"SPF   : {evidence.authentication.spf.upper()}")
    print(f"DKIM  : {evidence.authentication.dkim.upper()}")
    print(f"DMARC : {evidence.authentication.dmarc.upper()}")

    print("\n--- EXTRACTED OBSERVABLES ---")

    print(f"URLs    : {len(evidence.iocs.urls)}")
    for item in evidence.iocs.urls:
        print(f"  - {item}")

    print(f"Domains : {len(evidence.iocs.domains)}")
    for item in evidence.iocs.domains:
        print(f"  - {item}")

    print(f"IPs     : {len(evidence.iocs.ips)}")
    for item in evidence.iocs.ips:
        print(f"  - {item}")

    print(f"Emails  : {len(evidence.iocs.emails)}")
    for item in evidence.iocs.emails:
        print(f"  - {item}")

    print("\n--- ATTACHMENTS ---")

    if evidence.attachments:
        for attachment in evidence.attachments:
            print(f"\nFilename : {attachment.filename}")
            print(f"Type     : {attachment.mime_type}")
            print(f"Size     : {attachment.size_bytes} bytes")
            print(f"SHA-256  : {attachment.sha256}")
    else:
        print("No attachments detected.")

    print("\n--- SECURITY EVIDENCE SIGNALS ---")

    if evidence.evidence_signals:
        for signal in evidence.evidence_signals:
            print(
                f"[{signal['severity'].upper()}] "
                f"{signal['signal_id']} — "
                f"{signal['description']}"
            )
    else:
        print("No configured security anomalies detected.")

    print("\n" + "=" * 60)

    # Save complete machine-readable evidence
    output_path = "analysis_result.json"

    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(
            asdict(evidence),
            output_file,
            indent=4
        )

    print(f"Full evidence saved to: {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()