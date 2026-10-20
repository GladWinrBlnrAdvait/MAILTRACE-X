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

## Safety notes

- Treat email attachments as untrusted. MAILTRACE-X calculates metadata and hashes; it does not execute them.
- Threat intelligence enrichment can make network calls. Use API keys only through environment variables, never commits.
- The local SQLite case store is intended for development. Add authentication, access control, encryption, audit logging, and a production database before deploying with real email data.

## License and contributions

Choose and add a license before external distribution. Keep module boundaries intact, add tests with each change, and never commit real victim email content or credentials.
