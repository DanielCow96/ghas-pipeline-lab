"""Application configuration.

LAB NOTE: this module contains deliberate weaknesses. See docs/00-lab-guide.md.
Expected CodeQL rules: py/hardcoded-credentials, py/clear-text-storage-sensitive-data
"""

import os

# --- VULN 1: hardcoded credentials (CWE-798) -------------------------------
# CodeQL: py/hardcoded-credentials
# Realistic pattern: a "temporary" default that survived into production.
DB_USER = "svc_orders"
DB_PASSWORD = "Sup3rS3cret-Rotate-Me"  # noqa: S105
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "orders")

# --- VULN 2: hardcoded signing key (CWE-321) -------------------------------
# CodeQL: py/hardcoded-credentials
JWT_SIGNING_KEY = "dev-signing-key-do-not-use"

# Internal service allowlist used by app/integrations.py
PARTNER_HOST_ALLOWLIST = ["partner.example.com", "api.partner.example.com"]

# Where generated reports are written / read from.
REPORT_ROOT = os.getenv("REPORT_ROOT", "/var/lib/orders/reports")

# Feature flags
ENABLE_LEGACY_IMPORT = os.getenv("ENABLE_LEGACY_IMPORT", "true").lower() == "true"


def database_url() -> str:
    """Build a DSN. Credentials embedded here end up in logs and stack traces."""
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
