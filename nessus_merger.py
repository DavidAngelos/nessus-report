#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from lxml import etree


def merge_nessus_files(
    input_files: Iterable[str | Path],
    output_file: str | Path,
    report_name: Optional[str] = None,
) -> Path:
    """
    Merge multiple .nessus (XML) files into one by appending all ReportHost nodes
    into the first file's Report.
    """
    input_paths = [Path(p) for p in input_files]
    if len(input_paths) < 2:
        raise ValueError("Provide at least 2 .nessus files to merge.")

    for p in input_paths:
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")
        if p.suffix.lower() != ".nessus":
            raise ValueError(f"Not a .nessus file: {p}")

    # Secure parser settings
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        remove_comments=False,
        huge_tree=True,  # Nessus exports can be big
    )

    # Parse base
    base_tree = etree.parse(str(input_paths[0]), parser)
    base_root = base_tree.getroot()

    base_report = base_root.find(".//Report")
    if base_report is None:
        raise ValueError(f"Invalid .nessus structure (missing Report) in {input_paths[0]}")

    # Set merged report name (optional)
    if report_name:
        base_report.set("name", report_name)

    # Append ReportHost nodes from others
    for p in input_paths[1:]:
        t = etree.parse(str(p), parser)
        r = t.getroot().find(".//Report")
        if r is None:
            raise ValueError(f"Invalid .nessus structure (missing Report) in {p}")

        for host in r.findall("./ReportHost"):
            base_report.append(host)

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write
    base_tree.write(
        str(out_path),
        xml_declaration=True,
        encoding="utf-8",
        pretty_print=True,
    )

    return out_path


def _cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Merge multiple Nessus .nessus files into one.")
    parser.add_argument("inputs", nargs="+", help="Input .nessus files (2+)")
    parser.add_argument("-o", "--output", required=True, help="Output merged .nessus file")
    parser.add_argument("--name", default=None, help="Optional merged Report name")
    args = parser.parse_args()

    out = merge_nessus_files(args.inputs, args.output, args.name)
    print(f"Merged report written to: {out}")


if __name__ == "__main__":
    _cli()
