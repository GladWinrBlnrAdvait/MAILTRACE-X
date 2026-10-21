# MAILTRACE-X

> An explainable email-phishing investigation platform that turns an `.eml` file into forensic evidence, threat relationships, a detection verdict, and a shareable case report.

MAILTRACE-X is designed for investigation—not just classification. It keeps evidence visible so an analyst can see *why* an email was flagged.

```text
.eml upload → forensic evidence → threat correlation → detection + risk → dashboard/report
```

## What it does

| Layer | Capability | Owner |
| --- | --- | --- |
| Security evidence | MIME/header parsing, IOC extraction, attachment hashes, SPF/DKIM/DMARC evidence | Advait |
| Threat intelligence | IP/DNS/ASN enrichment and cross-case relationship graph | Abhay |
| Detection & platform | Explainable phishing detection, composite risk, FastAPI, dashboard, reports, validation | Aditya |

The platform deliberately separates **evidence** from **attribution**. A shared domain or IP is reported as a relationship; it is not presented as proof of an attacker.

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/GladWinrBlnrAdvait/MAILTRACE-X.git
cd MAILTRACE-X
python -m venv .venv
```

Activate the environment (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on macOS/Linux), then:

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Set `MAILTRACE_API_KEY` before deploying (the local prototype uses `mailtrace-dev-key`), then open [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/) and sign in with that key. Interactive API documentation is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). Set `MAILTRACE_ALLOWED_ORIGINS` to a comma-separated allowlist for a separate frontend origin.

To run the original command-line evidence pipeline:

```bash
python main.py samples/sample.eml
```

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Service health check |
| `POST` | `/api/analyze/email` | Upload an `.eml` file and create an investigation case |
| `GET` | `/api/cases` | List saved local cases |
| `GET` | `/api/case/{case_id}` | Fetch the normalized case result |
| `GET` | `/api/report/{case_id}` | Open a standalone HTML investigation report |
| `GET` | `/api/report/{case_id}/pdf` | Download a structured-evidence PDF report |

All case endpoints require `X-API-Key` (or `api_key` for an authenticated report download). The API rejects non-EML files, empty inputs, and uploads over 10 MB; component failures return stable error codes. Cases are stored locally in `mailtrace.db` (ignored by Git).

## Detection and risk methodology

The shipped **explainable logistic baseline** uses auditable features: suspicious language, URL/IP/attachment counts, authentication failures, header anomalies, Reply-To mismatch, and HTML presence. It returns the matched lexical terms (or the highest weighted TF-IDF terms for a trained model) with every verdict.

Risk is `clamp(round(45 × phishing_probability) + signal_points + URL_points + attachment_points + correlation_points, 0, 100)`. Signals, URLs, attachments, and graph entities are de-duplicated using stable identifiers before their capped contributions are applied. This is intentional: a duplicated parser finding or MIME part cannot raise a score twice.

This is a transparent prototype baseline—not a claim of production-grade model accuracy. To train an empirical TF-IDF + Logistic Regression model on a labelled dataset with `text` and `label` columns:

```bash
python ml/training/train_baseline.py path/to/emails.csv
```

The training command uses a stratified 80/20 held-out split and writes `ml/models/evaluation.json`, comparing the legacy lexical baseline against TF-IDF Logistic Regression on precision, recall, F1, and false-positive rate.

## Development and tests

```bash
python -m unittest discover -s tests -v
```

The tests cover parsing, header/authentication signals, IOC extraction, attachments, the end-to-end evidence pipeline, and Aditya’s detection/risk integration.

## Repository map

```text
evidence/                 Advait: email forensics and normalized EmailEvidence
threat_intelligence/      Abhay: IP and DNS lookups
correlation/              Abhay: graph and related-case correlation
backend/                  Aditya: API, detector, risk engine, reports, local persistence
dashboard/                Aditya: responsive analyst UI
ml/training/              Aditya: reproducible model-training entry point
tests/                    Regression and pipeline validation
samples/                  Safe demonstration EML inputs
```

## Static attachment analysis

`evidence/attachment_static.py` inspects attachment bytes in memory (nothing is executed, opened or extracted) and emits `ATT-xxx` signals into `evidence_signals`:

| Signal | Meaning |
|--------|---------|
| ATT-001 | File content does not match its extension |
| ATT-002 | Double extension or right-to-left-override filename |
| ATT-003 | High-risk file type (executable, script, disk image) |
| ATT-004 / ATT-005 | Office macros present / macro runs automatically (`oletools`) |
| ATT-006 / ATT-007 / ATT-008 | PDF JavaScript / auto-open action / `/Launch` action |
| ATT-009 / ATT-010 | Archive contains executables / archive is password-protected |

Limitations: PDF checks look for name tokens (raw and Flate-decoded), so heavily obfuscated PDFs can evade them; macro detail needs `oletools`; only ZIP archives are listed.

## Sample corpus

`samples/generate_corpus.py` builds safe, synthetic demo emails (reserved `example.*` domains, documentation IP ranges, harmless stand-in attachments):

```bash
python samples/generate_corpus.py --vba-bin path/to/vbaProject.bin
```

`campaign_a_double_extension.eml` and `campaign_b_followup.eml` share `billing-update.example.org` for the related-case demo. `phishing_brand_spoof.eml` exercises the header checks, the Received timeline, a defanged link and an IPv6 hop (regenerate just it with `--only phishing_brand_spoof`). Some antivirus products may flag the macro sample; it only carries a benign example macro.

## Header forensics and Received timeline

| Signal | Meaning |
|--------|---------|
| HDR-001 / HDR-002 | From vs Reply-To / Return-Path domain mismatch |
| HDR-003 | Display name shows a different email address or domain than the real sender |
| HDR-004 | Display name claims a known brand the sender domain does not own (small heuristic list) |
| HDR-005 | Message-ID domain unrelated to the From domain (low) |
| HDR-006 | Message-ID header missing (low) |
| HDR-007 | Received timestamps go backwards by more than 5 minutes (low) |
| PARSE-001 | MIME nesting too deep to analyze fully (possible filter evasion) |

`evidence/received_chain.py` turns the Received headers into an ordered hop list (oldest first: sending host, IP, receiving host, protocol, timestamp, delay) in `received_hops`, plus a best-effort `origin_ip` (first non-internal IP). Headers added by the sender's own system can be forged, so only hops added by servers you trust are reliable. HDR-004 and HDR-005 can fire on legitimate third-party senders (mailing services), so treat them as hints.

## IOC extraction notes

Defanged indicators (`hxxps://`, `[.]`, `[@]`, `(dot)`) are recognized and returned in normal form. IPv4 and IPv6 are extracted; loopback, private, link-local, multicast and reserved addresses are filtered out of `iocs.ips` (they stay visible in `received_hops`). Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are deliberately kept so demo data works.

## Robustness

Malformed emails, odd encodings, missing headers and extreme MIME nesting are covered by `tests/test_robustness.py`. Two quadratic-time regexes (email extraction and PDF stream scanning) that hostile input could use to hang the server were replaced with bounded, linear-time versions; the tests include speed limits.

## Optional VirusTotal enrichment (hash reputation + sandbox behaviour)

`evidence/sandbox.py` looks up each attachment's SHA-256 on VirusTotal. **Only the hash is sent; files are never uploaded or executed.** It is OFF unless both variables are set:

```powershell
$env:MAILTRACE_SANDBOX_PROVIDER = "virustotal"
$env:VT_API_KEY = "<your key>"      # never commit this
```

| Signal | Meaning |
|--------|---------|
| SBX-001 | Antivirus engines flag the attachment (>=10 high, 3-9 medium, 1-2 low) |
| SBX-002 | At least half of the sandboxes returned a non-clean verdict (medium) |
| SBX-003 | Sandbox observed MITRE ATT&CK techniques (informational) |

Notes: free tier is 4 requests/minute, so a built-in limiter returns `rate_limited` instead of blocking; a file VirusTotal has never seen returns `not_found` (neutral); any failure (no key, timeout, 403, 429) is non-fatal. Sandbox text is untrusted, so the report template must HTML-escape it. Sandbox network traffic is intentionally not turned into IOCs. Thresholds are heuristics, not validated. Uploading unknown files for fresh analysis is not implemented.

## Safety notes

- Treat email attachments as untrusted. MAILTRACE-X calculates metadata and hashes; it does not execute them.
- Threat intelligence enrichment can make network calls. Use API keys only through environment variables, never commits.
- The local SQLite case store is intended for development. Add authentication, access control, encryption, audit logging, and a production database before deploying with real email data.

## License and contributions

Choose and add a license before external distribution. Keep module boundaries intact, add tests with each change, and never commit real victim email content or credentials.
