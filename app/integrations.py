"""Outbound calls to partner systems.

LAB NOTE: deliberate weaknesses. Expected CodeQL rules:
  py/full-ssrf (CWE-918)
  py/request-without-cert-validation (CWE-295)
  py/incomplete-url-substring-sanitization (CWE-20)
"""

import requests

from app.config import PARTNER_HOST_ALLOWLIST

TIMEOUT = 10


# --- VULN 11: server-side request forgery (CWE-918) -----------------------
# CodeQL: py/full-ssrf
# A user-supplied URL is fetched by the server, which sits inside the VPC and
# can reach the cloud metadata endpoint and every internal admin panel.
def fetch_partner_document(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in PARTNER_HOST_ALLOWLIST:
        raise ValueError("URL is not in the partner allowlist")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("URL must not include credentials or a custom port")
    safe_path = parsed.path or "/"
    safe_url = f"https://{parsed.hostname}{safe_path}"
    if parsed.query:
        safe_url = f"{safe_url}?{parsed.query}"
    response = requests.get(safe_url, timeout=TIMEOUT, allow_redirects=False)
    return response.text


# --- VULN 12: TLS verification disabled (CWE-295) -------------------------
# CodeQL: py/request-without-cert-validation
# Added years ago to work around a self-signed cert in staging. Still here.
def push_order_status(order_id: int, status: str) -> int:
    response = requests.post(
        "https://api.partner.example.com/v1/orders/status",
        json={"order_id": order_id, "status": status},
        verify=False,  # noqa: S501
        timeout=TIMEOUT,
    )
    return response.status_code


# --- VULN 13: incomplete URL sanitisation (CWE-20) ------------------------
# CodeQL: py/incomplete-url-substring-sanitization
# "partner.example.com.attacker.tld" and "attacker.tld/?partner.example.com"
# both satisfy this check.
def fetch_if_allowed(url: str) -> str | None:
    for host in PARTNER_HOST_ALLOWLIST:
        if host in url:
            return requests.get(url, timeout=TIMEOUT).text
    return None


# --- REFERENCE FIX --------------------------------------------------------
from urllib.parse import urlparse  # noqa: E402


def fetch_if_allowed_safe(url: str) -> str | None:
    """Parse the URL and compare the *host component* exactly.

    A complete SSRF fix also resolves the hostname and rejects private,
    loopback and link-local address ranges (169.254.169.254 in particular),
    and disables redirects so a 302 cannot walk the request back inside.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    if parsed.hostname not in PARTNER_HOST_ALLOWLIST:
        return None
    return requests.get(url, timeout=TIMEOUT, allow_redirects=False).text
