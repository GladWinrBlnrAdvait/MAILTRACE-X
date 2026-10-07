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

Open [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/) and upload an `.eml` file. Interactive API documentation is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

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

The API rejects non-EML files, empty inputs, and uploads over 10 MB. Cases are stored locally in `mailtrace.db` (ignored by Git).

## Detection and risk methodology

The shipped **explainable logistic baseline** uses auditable features: suspicious language, URL/IP/attachment counts, authentication failures, header anomalies, Reply-To mismatch, and HTML presence. The risk engine then combines the detection probability with deterministic forensic evidence and optional cross-case correlation.

This is a transparent prototype baseline—not a claim of production-grade model accuracy. To train an empirical TF-IDF + Logistic Regression model on a labelled dataset with `text` and `label` columns:

```bash
python ml/training/train_baseline.py path/to/emails.csv
```

Track precision, recall, F1, false-positive rate, processing time, and dataset provenance before reporting evaluation results.

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

## Safety notes

- Treat email attachments as untrusted. MAILTRACE-X calculates metadata and hashes; it does not execute them.
- Threat intelligence enrichment can make network calls. Use API keys only through environment variables, never commits.
- The local SQLite case store is intended for development. Add authentication, access control, encryption, audit logging, and a production database before deploying with real email data.

## License and contributions

Choose and add a license before external distribution. Keep module boundaries intact, add tests with each change, and never commit real victim email content or credentials.
