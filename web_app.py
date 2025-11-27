#!/usr/bin/env python3
import os
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    request,
    send_file,
    render_template_string,
    redirect,
    url_for,
    flash,
)

from nessus import NessusReportGenerator  # <-- import your existing class

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # needed for flash messages

# Simple, modern-ish HTML template using inline CSS
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nessus Report Portal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --bg: #05060a;
            --bg-elevated: #0b0e12;
            --bg-card: #111418;
            --border-soft: #1e242b;
            --border-strong: #2a323c;
            --accent: #2faa71;          /* Softer Proton-ish green */
            --accent-hover: #289162;
            --accent-bg: rgba(47,170,113,0.12);
            --text: #f0f3f5;
            --muted: #9aa5b1;
            --radius-lg: 12px;
            --radius-xl: 16px;
            --shadow-soft: 0 2px 6px rgba(0,0,0,0.28);  /* Soft, Proton-style low shadow */
            --transition-fast: 0.15s ease;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .wrapper {
            width: 100%;
            max-width: 900px;
            padding: 20px;
        }

        .card {
            background: var(--bg-card);
            border-radius: var(--radius-xl);
            border: 1px solid var(--border-soft);
            box-shadow: var(--shadow-soft);
            padding: 22px 26px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
        }

        .title-block {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .title {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .subtitle {
            font-size: 0.9rem;
            color: var(--muted);
        }

        .pill {
            font-size: 0.7rem;
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 4px 9px;
            color: var(--muted);
        }

        .grid-layout {
            display: grid;
            grid-template-columns: minmax(0, 1.8fr) minmax(0, 1.2fr);
            gap: 22px;
        }

        .dropzone {
            border: 1px solid var(--border-soft);
            background: var(--bg-elevated);
            border-radius: var(--radius-lg);
            padding: 20px 20px;
            cursor: pointer;
            transition: background var(--transition-fast), border var(--transition-fast);
        }

        .dropzone:hover {
            background: #15191f;
            border-color: var(--border-strong);
        }

        .dropzone-icon-circle {
            width: 38px;
            height: 38px;
            background: var(--bg-card);
            border: 1px solid var(--border-soft);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 10px;
        }

        .dropzone-main {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .dropzone-title {
            font-size: 0.95rem;
            font-weight: 500;
        }

        .dropzone-subtitle {
            font-size: 0.8rem;
            color: var(--muted);
        }

        input[type="file"] {
            display: none;
        }

        .side-panel {
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-lg);
            padding: 16px 18px;
        }

        .side-title {
            font-size: 0.9rem;
            font-weight: 500;
            margin-bottom: 4px;
        }

        .side-subtitle {
            font-size: 0.78rem;
            color: var(--muted);
            margin-bottom: 12px;
        }

        .checkbox-row {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.82rem;
        }

        .checkbox-item input {
            accent-color: var(--accent);
            cursor: pointer;
        }

        .info-box {
            margin-top: 12px;
            background: var(--bg);
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-lg);
            padding: 10px 12px;
            font-size: 0.78rem;
            color: var(--muted);
        }

        .actions {
            display: flex;
            justify-content: flex-end;
            margin-top: 20px;
        }

        .btn-primary {
            background: var(--accent);
            border: none;
            border-radius: 999px;
            padding: 10px 22px;
            color: #fff;
            font-size: 0.9rem;
            cursor: pointer;
            transition: background var(--transition-fast);
        }

        .btn-primary:hover {
            background: var(--accent-hover);
        }

        .btn-primary:active {
            background: #1e7d4c;
        }

        .flash {
            margin-top: 10px;
            font-size: 0.78rem;
            padding: 8px;
            border-radius: var(--radius-lg);
        }

        .flash-error {
            background: rgba(180,35,35,0.15);
            border: 1px solid rgba(180,35,35,0.35);
            color: #ffbaba;
        }

        @media (max-width: 820px) {
            .grid-layout {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>
<div class="wrapper">
    <div class="card">
        <div class="header">
            <div class="title-block">
                <div class="title">Nessus Report Portal</div>
                <div class="subtitle">Upload a Nessus CSV export and generate customer-ready reports.</div>
            </div>
            <div class="pill">Internal tool</div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}
              <div class="flash flash-{{ category }}">{{ msg }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('generate') }}" enctype="multipart/form-data">
            <div class="grid-layout">
                <label class="dropzone" for="csv-file">
                    <div class="dropzone-icon-circle">
                        <span class="dropzone-icon">📄</span>
                    </div>
                    <div class="dropzone-main">
                        <div class="dropzone-title" id="file-label">
                            Drop your Nessus CSV here or click to browse
                        </div>
                        <div class="dropzone-subtitle">Nessus CSV export only. Processing is local.</div>
                    </div>
                    <input type="file" id="csv-file" name="csv_file" accept=".csv" required>
                </label>

                <div class="side-panel">
                    <div class="side-title">Output formats</div>
                    <div class="side-subtitle">
                        Select one or more outputs. Multiple selections download a ZIP.
                    </div>

                    <div class="checkbox-row">
                        <div class="checkbox-item">
                            <input type="checkbox" id="fmt_csv" name="format_csv" checked>
                            <label for="fmt_csv">CSV – executive summary & detailed findings</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="fmt_excel" name="format_excel" checked>
                            <label for="fmt_excel">Excel – multi-sheet report with charts</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="fmt_html" name="format_html" checked>
                            <label for="fmt_html">HTML – styled customer-ready report</label>
                        </div>
                    </div>

                    <div class="info-box">
                        Findings filtered to <code>Low</code>, <code>Medium</code>, <code>High</code>, <code>Critical</code>.
                    </div>
                </div>
            </div>

            <div class="actions">
                <button type="submit" class="btn-primary">Generate report</button>
            </div>
        </form>
    </div>
</div>

<script>
    const fileInput = document.getElementById('csv-file');
    const fileLabel = document.getElementById('file-label');

    fileInput.addEventListener('change', () => {
        fileLabel.textContent =
            fileInput.files.length > 0
                ? fileInput.files[0].name
                : "Drop your Nessus CSV here or click to browse";
    });
</script>

</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)


@app.route("/generate", methods=["POST"])
def generate():
    file = request.files.get("csv_file")
    if not file or file.filename == "":
        flash("Please upload a Nessus CSV file.", "error")
        return redirect(url_for("index"))

    # Check which formats are requested
    want_csv = "format_csv" in request.form
    want_excel = "format_excel" in request.form
    want_html = "format_html" in request.form

    if not (want_csv or want_excel or want_html):
        flash("Please select at least one output format.", "error")
        return redirect(url_for("index"))

    # Temp directory for this request
    temp_dir = tempfile.mkdtemp(prefix="nessus_report_")
    csv_path = os.path.join(temp_dir, file.filename)
    file.save(csv_path)

    # Run your existing generator
    generator = NessusReportGenerator(csv_path)
    if not generator.load_data():
        flash("Failed to load CSV. Check that this is a Nessus CSV export.", "error")
        return redirect(url_for("index"))

    generator.clean_data()
    generator.generate_summary()

    # Output prefix in the temp dir
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = os.path.join(temp_dir, f"report_{timestamp}")

    generated_files = []

    if want_csv:
        summary_file, detailed_file = generator.export_to_csv(output_prefix)
        generated_files.extend([summary_file, detailed_file])

    if want_excel:
        excel_file = generator.export_to_excel(output_prefix)
        generated_files.append(excel_file)

    if want_html:
        html_file = generator.export_to_html(output_prefix)
        generated_files.append(html_file)

    # If only one file, send it directly
    if len(generated_files) == 1:
        return send_file(generated_files[0], as_attachment=True)

    # Otherwise, zip them up
    zip_path = os.path.join(temp_dir, "nessus_report_bundle.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in generated_files:
            zf.write(path, arcname=os.path.basename(path))

    return send_file(zip_path, as_attachment=True)


if __name__ == "__main__":
    # Run the app locally
    app.run(host="0.0.0.0", port=5000, debug=True)
