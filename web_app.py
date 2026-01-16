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

from werkzeug.utils import secure_filename

from nessus import NessusReportGenerator  # <-- import your existing class
from nessus_merger import merge_nessus_files

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

        .tabs {
            display: flex;
            gap: 8px;
            margin: 12px 0 18px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-soft);
        }

        .tab {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
            color: var(--muted);
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 0.82rem;
            transition: background var(--transition-fast), border var(--transition-fast), color var(--transition-fast);
        }

        .tab:hover {
            background: #15191f;
            border-color: var(--border-strong);
            color: var(--text);
        }

        .tab.active {
            background: var(--bg-card);
            border-color: var(--border-strong);
            color: var(--text);
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

        .dropzone.dragover {
            background: #181d24;
            border-color: var(--border-strong);
        }

        .file-list {
            margin-top: 10px;
            font-size: 0.78rem;
            color: var(--muted);
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .file-pill {
            background: var(--bg-card);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 3px 8px;
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

        <div class="tabs">
            <a class="tab active" href="{{ url_for('index') }}">CSV → Reports</a>
            <a class="tab" href="{{ url_for('merge_page') }}">Merge .nessus</a>
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
                            Drop one or more Nessus CSVs here or click to browse
                        </div>
                        <div class="dropzone-subtitle">
                            Nessus CSV exports only. Processing is local.
                        </div>
                        <div class="file-list" id="file-list"></div>
                    </div>
                    <input type="file" id="csv-file" name="csv_file" accept=".csv" multiple required>
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
    const fileInput  = document.getElementById('csv-file');
    const fileLabel  = document.getElementById('file-label');
    const fileListEl = document.getElementById('file-list');
    const dropzone   = document.querySelector('.dropzone');

    function updateFileList(files) {
        fileListEl.innerHTML = '';

        if (!files || files.length === 0) {
            fileLabel.textContent = "Drop one or more Nessus CSVs here or click to browse";
            return;
        }

        // Show actual filenames in the main label (instead of "N files selected")
        const names = Array.from(files).map(f => f.name);
        if (names.length === 1) {
            fileLabel.textContent = names[0];
        } else if (names.length <= 3) {
            fileLabel.textContent = names.join(", ");
        } else {
            fileLabel.textContent = names.slice(0, 3).join(", ") + ` (+${names.length - 3} more)`;
        }

        Array.from(files).forEach(f => {
            const pill = document.createElement('span');
            pill.className = 'file-pill';
            pill.textContent = f.name;
            fileListEl.appendChild(pill);
        });
    }

    fileInput.addEventListener('change', () => {
        updateFileList(fileInput.files);
    });

    // Drag & drop handling
    ['dragenter', 'dragover'].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'dragend', 'drop'].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    dropzone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (!files || files.length === 0) return;

        const csvFiles = Array.from(files).filter(f => f.name.toLowerCase().endsWith('.csv'));
        if (csvFiles.length === 0) return;

        const dt = new DataTransfer();
        csvFiles.forEach(f => dt.items.add(f));
        fileInput.files = dt.files;

        updateFileList(fileInput.files);
    });

</script>

</body>
</html>
"""

MERGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nessus Report Portal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        /* Reuse the same CSS as INDEX_HTML (copy/paste the <style> block from INDEX_HTML)
           OR keep it simple by duplicating exactly what you already have. */

        :root {
            --bg: #05060a;
            --bg-elevated: #0b0e12;
            --bg-card: #111418;
            --border-soft: #1e242b;
            --border-strong: #2a323c;
            --accent: #2faa71;
            --accent-hover: #289162;
            --text: #f0f3f5;
            --muted: #9aa5b1;
            --radius-lg: 12px;
            --radius-xl: 16px;
            --shadow-soft: 0 2px 6px rgba(0,0,0,0.28);
            --transition-fast: 0.15s ease;
        }

        * { box-sizing: border-box; }

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

        .wrapper { width: 100%; max-width: 900px; padding: 20px; }

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
            margin-bottom: 10px;
        }

        .title { font-size: 1.3rem; font-weight: 600; }
        .subtitle { font-size: 0.9rem; color: var(--muted); }

        .pill {
            font-size: 0.7rem;
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 4px 9px;
            color: var(--muted);
        }

        .tabs {
            display: flex;
            gap: 8px;
            margin: 12px 0 18px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-soft);
        }

        .tab {
            display: inline-flex;
            align-items: center;
            text-decoration: none;
            color: var(--muted);
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 7px 12px;
            font-size: 0.82rem;
            transition: background var(--transition-fast), border var(--transition-fast), color var(--transition-fast);
        }

        .tab:hover {
            background: #15191f;
            border-color: var(--border-strong);
            color: var(--text);
        }

        .tab.active {
            background: var(--bg-card);
            border-color: var(--border-strong);
            color: var(--text);
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

        .dropzone:hover { background: #15191f; border-color: var(--border-strong); }
        .dropzone.dragover { background: #181d24; border-color: var(--border-strong); }

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

        .dropzone-title { font-size: 0.95rem; font-weight: 500; }
        .dropzone-subtitle { font-size: 0.8rem; color: var(--muted); }

        .file-list {
            margin-top: 10px;
            font-size: 0.78rem;
            color: var(--muted);
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .file-pill {
            background: var(--bg-card);
            border: 1px solid var(--border-soft);
            border-radius: 999px;
            padding: 3px 8px;
        }

        input[type="file"] { display: none; }

        .side-panel {
            background: var(--bg-elevated);
            border: 1px solid var(--border-soft);
            border-radius: var(--radius-lg);
            padding: 16px 18px;
        }

        .side-title { font-size: 0.9rem; font-weight: 500; margin-bottom: 4px; }
        .side-subtitle { font-size: 0.78rem; color: var(--muted); margin-bottom: 12px; }

        .field-label {
            font-size: 0.78rem;
            color: var(--muted);
            margin: 12px 0 6px;
        }

        .text-input {
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-soft);
            border-radius: 10px;
            padding: 10px 12px;
            color: var(--text);
            outline: none;
        }

        .text-input:focus {
            border-color: var(--border-strong);
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

        .btn-primary:hover { background: var(--accent-hover); }

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
            .grid-layout { grid-template-columns: 1fr; }
        }
    </style>
</head>

<body>
<div class="wrapper">
    <div class="card">
        <div class="header">
            <div>
                <div class="title">Nessus Report Portal</div>
                <div class="subtitle">Merge multiple .nessus XML exports into a single .nessus file.</div>
            </div>
            <div class="pill">Internal tool</div>
        </div>

        <div class="tabs">
            <a class="tab" href="{{ url_for('index') }}">CSV → Reports</a>
            <a class="tab active" href="{{ url_for('merge_page') }}">Merge .nessus</a>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, msg in messages %}
              <div class="flash flash-{{ category }}">{{ msg }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('merge_submit') }}" enctype="multipart/form-data">
            <div class="grid-layout">
                <label class="dropzone" for="nessus-file" id="merge-dropzone">
                    <div class="dropzone-icon-circle">
                        <span class="dropzone-icon">📄</span>
                    </div>
                    <div>
                        <div class="dropzone-title" id="merge-label">
                            Drop 2+ .nessus files here or click to browse
                        </div>
                        <div class="dropzone-subtitle">
                            .nessus files are XML exports from Nessus.
                        </div>
                        <div class="file-list" id="merge-file-list"></div>
                    </div>
                    <input type="file" id="nessus-file" name="nessus_files" accept=".nessus" multiple required>
                </label>

                <div class="side-panel">
                    <div class="side-title">Merge options</div>
                    <div class="side-subtitle">Optional settings for the merged report.</div>

                    <div class="field-label">Merged report name (optional)</div>
                    <input class="text-input" type="text" name="report_name" placeholder="e.g. Merged Report">

                    <div class="field-label">Output</div>
                    <div class="side-subtitle">Downloads a merged <code>.nessus</code> file.</div>
                </div>
            </div>

            <div class="actions">
                <button type="submit" class="btn-primary">Merge .nessus</button>
            </div>
        </form>
    </div>
</div>

<script>
    const mergeInput  = document.getElementById('nessus-file');
    const mergeLabel  = document.getElementById('merge-label');
    const mergeListEl = document.getElementById('merge-file-list');
    const mergeZone   = document.getElementById('merge-dropzone');

    function updateMergeList(files) {
        mergeListEl.innerHTML = '';
        if (!files || files.length === 0) {
            mergeLabel.textContent = "Drop 2+ .nessus files here or click to browse";
            return;
        }

        const names = Array.from(files).map(f => f.name);
        if (names.length === 1) {
            mergeLabel.textContent = names[0];
        } else if (names.length <= 3) {
            mergeLabel.textContent = names.join(", ");
        } else {
            mergeLabel.textContent = names.slice(0, 3).join(", ") + ` (+${names.length - 3} more)`;
        }

        Array.from(files).forEach(f => {
            const pill = document.createElement('span');
            pill.className = 'file-pill';
            pill.textContent = f.name;
            mergeListEl.appendChild(pill);
        });
    }

    mergeInput.addEventListener('change', () => updateMergeList(mergeInput.files));

    ['dragenter', 'dragover'].forEach(evt => {
        mergeZone.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            mergeZone.classList.add('dragover');
        });
    });

    ['dragleave', 'dragend', 'drop'].forEach(evt => {
        mergeZone.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            mergeZone.classList.remove('dragover');
        });
    });

    mergeZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (!files || files.length === 0) return;

        const nessusFiles = Array.from(files).filter(f => f.name.toLowerCase().endsWith('.nessus'));
        if (nessusFiles.length === 0) return;

        const dt = new DataTransfer();
        nessusFiles.forEach(f => dt.items.add(f));
        mergeInput.files = dt.files;

        updateMergeList(mergeInput.files);
    });
</script>

</body>
</html>
"""



@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/merge", methods=["GET"])
def merge_page():
    return render_template_string(MERGE_HTML)


@app.route("/merge", methods=["POST"])
def merge_submit():
    files = request.files.getlist("nessus_files")
    files = [f for f in files if f and f.filename]

    if len(files) < 2:
        flash("Please upload at least two .nessus files to merge.", "error")
        return redirect(url_for("merge_page"))

    temp_dir = tempfile.mkdtemp(prefix="nessus_merge_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    input_paths = []
    for f in files:
        safe_name = secure_filename(f.filename)
        if not safe_name.lower().endswith(".nessus"):
            flash(f"Skipping non-.nessus file: {f.filename}", "error")
            continue

        p = os.path.join(temp_dir, safe_name)
        f.save(p)
        input_paths.append(p)

    if len(input_paths) < 2:
        flash("Not enough valid .nessus files after filtering.", "error")
        return redirect(url_for("merge_page"))

    report_name = (request.form.get("report_name") or "").strip() or None
    merged_path = os.path.join(temp_dir, f"merged_{timestamp}.nessus")

    try:
        merge_nessus_files(input_paths, merged_path, report_name=report_name)
    except Exception as e:
        flash(f"Merge failed: {e}", "error")
        return redirect(url_for("merge_page"))

    return send_file(merged_path, as_attachment=True)

@app.route("/generate", methods=["POST"])
def generate():
    files = request.files.getlist("csv_file")

    # Validate file list
    files = [f for f in files if f and f.filename]
    if not files:
        flash("Please upload at least one Nessus CSV file.", "error")
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    generated_files = []

    for file in files:
        safe_name = secure_filename(file.filename)
        if not safe_name.lower().endswith(".csv"):
            flash(f"Skipping non-CSV file: {file.filename}", "error")
            continue

        csv_path = os.path.join(temp_dir, safe_name)
        file.save(csv_path)

        generator = NessusReportGenerator(csv_path)
        if not generator.load_data():
            flash(f"Failed to load CSV: {file.filename}", "error")
            continue

        generator.clean_data()
        generator.generate_summary()

        # Use original filename stem as part of output prefix
        stem = Path(safe_name).stem
        output_prefix = os.path.join(temp_dir, f"{stem}_{timestamp}")

        if want_csv:
            summary_file, detailed_file = generator.export_to_csv(output_prefix)
            generated_files.extend([summary_file, detailed_file])

        if want_excel:
            excel_file = generator.export_to_excel(output_prefix)
            generated_files.append(excel_file)

        if want_html:
            html_file = generator.export_to_html(output_prefix)
            generated_files.append(html_file)

    if not generated_files:
        flash("No reports were generated. Check input files and formats.", "error")
        return redirect(url_for("index"))

    # If only one file produced, send it directly
    if len(generated_files) == 1:
        return send_file(generated_files[0], as_attachment=True)

    # Otherwise, zip all outputs
    zip_path = os.path.join(temp_dir, f"nessus_reports_{timestamp}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in generated_files:
            zf.write(path, arcname=os.path.basename(path))

    return send_file(zip_path, as_attachment=True)

if __name__ == "__main__":
    # Run the app locally
    app.run(host="0.0.0.0", port=5000, debug=True)
