"""Report generation and retrieval.

LAB NOTE: deliberate weaknesses. Expected CodeQL rules:
  py/command-line-injection (CWE-78)
  py/path-injection (CWE-22)
  py/insecure-temporary-file (CWE-377)
"""

import os
import subprocess  # noqa: S404
import tempfile

from app.config import REPORT_ROOT


# --- VULN 8: OS command injection (CWE-78) --------------------------------
# CodeQL: py/command-line-injection
# shell=True plus an interpolated, user-controlled filename.
def convert_report_to_pdf(report_name: str) -> str:
    src = os.path.join(REPORT_ROOT, report_name)
    dst = src.replace(".html", ".pdf")
    subprocess.check_output(["wkhtmltopdf", src, dst])  # noqa: S603
    return dst


# --- VULN 9: path traversal (CWE-22) --------------------------------------
# CodeQL: py/path-injection
# "../../etc/passwd" walks straight out of REPORT_ROOT.
def read_report(report_name: str) -> str:
    path = os.path.join(REPORT_ROOT, report_name)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --- VULN 10: insecure temporary file (CWE-377) ---------------------------
# CodeQL: py/insecure-temporary-file
def stage_export(contents: str) -> str:
    path = os.path.join(tempfile.gettempdir(), "orders-export.csv")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(contents)
    return path


# --- REFERENCE FIXES ------------------------------------------------------
def convert_report_to_pdf_safe(report_name: str) -> str:
    src = _resolve_inside_report_root(report_name)
    dst = src.rsplit(".", 1)[0] + ".pdf"
    # No shell, argument list, validated path.
    subprocess.check_output(["wkhtmltopdf", src, dst])  # noqa: S603
    return dst


def read_report_safe(report_name: str) -> str:
    with open(_resolve_inside_report_root(report_name), encoding="utf-8") as fh:
        return fh.read()


def _resolve_inside_report_root(report_name: str) -> str:
    """Normalise first, then prove the result is still under REPORT_ROOT."""
    root = os.path.realpath(REPORT_ROOT)
    candidate = os.path.realpath(os.path.join(root, report_name))
    if not candidate.startswith(root + os.sep):
        raise ValueError("report path escapes the report root")
    return candidate


def stage_export_safe(contents: str) -> str:
    fd, path = tempfile.mkstemp(prefix="orders-export-", suffix=".csv")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(contents)
    return path
