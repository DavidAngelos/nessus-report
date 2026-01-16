# Nessus CSV Report Generator/Merger

This project provides a simple way to transform Nessus scan outputs into clear, customer-friendly reports, as well as merge multiple Nessus scans into a single export.

## Features

- Produces Executive Summary and Detailed Findings views
- Supports CSV, Excel (XLSX), and HTML outputs
- Handles multiple CSV inputs (each CSV is treated as a separate project)
- Includes a utility to merge multiple Nessus .nessus files into one
- Provides a simple web interface for reporting and .nessus merging

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

The tool can be used either from the command line or through the web interface.

#### Command-line usage (CSV reports)

Generate reports from a single Nessus CSV file:
```bash
python3 nessus.py path/to/nessus.csv
```

Generate reports from multiple CSV files (each CSV produces its own outputs):
```bash
python3 nessus.py scan1.csv scan2.csv scan3.csv
```

Use a custom output prefix:
```bash
python3 nessus.py scan.csv -o customer_name
```

Limit the output format(Available formats: csv, excel, html, all):
```bash
python3 nessus.py scan.csv -f excel
```

#### Command-line usage (.nessus merge)

Merge multiple Nessus .nessus files into a single combined report:
```bash
python3 nessus_merger.py scan1.nessus scan2.nessus -o merged_report.nessus
```

Optionally set a custom report name inside the merged file:
```bash
python3 nessus_merger.py scan1.nessus scan2.nessus -o merged_report.nessus --name "Merged Report"
```

#### Web Interface (Optional)

The web interface provides two separate workflows:

- CSV → Reports
Upload one or more Nessus CSV files and generate reports in CSV, Excel, or HTML format.

- Merge .nessus
Upload multiple .nessus files and download a single merged .nessus export.

All processing is performed locally on the server running the application.

You can also run a simple local web interface to upload Nessus CSVs and download reports:

```bash
python web_app.py
```

Then open `http://localhost:5000` in your browser.

## Input CSV expectations

This script is tolerant of missing fields, but works best when these columns are present (as in standard Nessus CSVs):
- Name, Risk, Host, Port, Protocol
- Synopsis, Description, Solution, CVE
- CVSS v3.0 Base Score, CVSS v2.0 Base Score

## Notes

- Informational findings are filtered out by default. Only Low, Medium, High, and Critical severities are included in reports