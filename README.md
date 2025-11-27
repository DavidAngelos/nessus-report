# Nessus CSV Report Generator

Convert **Nessus** CSV exports into professional, customer-ready reports (CSV, Excel with charts, and HTML).

## Features

- Cleans & standardizes Nessus CSV data (encoding fallback, column trimming, text cleanup)
- Filters common informational plugin noise
- Severity & CVSS aggregation with unified `CVSS_Score` (v3 preferred, v2 fallback)
- Executive summary, host summary, and detailed findings
- **Excel** output with charts (pie: findings by risk; bar: top hosts & top vulns)
- **HTML** report with color-coded findings table
- Filters findings to security-relevant severities only (`Low`, `Medium`, `High`, `Critical`)
- Optional local web UI (Flask) for uploading Nessus CSVs and downloading reports


## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
# All formats (default)
python3 nessus.py path/to/nessus.csv

# Specify output prefix and format
python3 nessus.py path/to/nessus.csv -o acme_q3 -f excel
python3 nessus.py path/to/nessus.csv -o acme_q3 -f html
python3 nessus.py path/to/nessus.csv -o acme_q3 -f csv
```

Outputs are timestamped, e.g.:

- acme_q3_executive_summary_YYYYMMDD_HHMMSS.csv
- acme_q3_detailed_findings_YYYYMMDD_HHMMSS.csv
- acme_q3_security_assessment_YYYYMMDD_HHMMSS.xlsx
- acme_q3_security_report_YYYYMMDD_HHMMSS.html

## Input CSV expectations

This script is tolerant of missing fields, but works best when these columns are present (as in standard Nessus CSVs):
- Name, Risk, Host, Port, Protocol
- Synopsis, Description, Solution, CVE
- CVSS v3.0 Base Score, CVSS v2.0 Base Score

### Optional: Web UI

You can also run a simple local web interface to upload Nessus CSVs and download reports:

```bash
python web_app.py
```

Then open `http://localhost:5000` in your browser.

## Notes

- Only `Low`, `Medium`, `High`, and `Critical` severities are included in the main statistics and detailed findings.  
- If present, purely informational items (`Risk == "None"` or similar) are ignored in the customer-facing outputs.
- Severity order: Critical > High > Medium > Low > None.
- CVSS metrics prefer v3; v2 is used when v3 is missing.