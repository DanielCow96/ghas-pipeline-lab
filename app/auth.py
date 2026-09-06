"""Authentication helpers.

LAB NOTE: deliberate weaknesses. Expected CodeQL rules:
  py/weak-sensitive-data-hashing (CWE-327/916)
  py/clear-text-logging-sensitive-data (CWE-312/532)
  py/hardcoded-credentials (CWE-798)
"""

import hashlib
import hmac
import logging
import os

from app.config import JWT_SIGNING_KEY
from app.db import get_connection

log = logging.getLogger("orders.auth")
_PASSWORD_HASH_SALT = b"orders-lab-password-salt"
_PASSWORD_HASH_ITERATIONS = 480_000


# --- VULN 5: weak hash for password storage (CWE-916) ----------------------
# CodeQL: py/weak-sensitive-data-hashing
# MD5 is fast and unsalted here — a leaked table is cracked offline in minutes.
def hash_password(password: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        _PASSWORD_HASH_SALT,
        _PASSWORD_HASH_ITERATIONS,
    )
    return digest.hex()


# --- VULN 6: sensitive data written to logs (CWE-532) ---------------------
# CodeQL: py/clear-text-logging-sensitive-data
def authenticate(username: str, password: str) -> dict | None:
    safe_username = username.replace("\r", "\\r").replace("\n", "\\n")
    log.info("login attempt user=%s", safe_username)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        return None
    if row["password_hash"] != hash_password(password):
        return None
    return {"username": row["username"], "role": row["role"]}


# --- VULN 7: timing-unsafe token comparison -------------------------------
# Not always flagged by the default suite — a good "what the scanner misses"
# discussion point during triage.
def verify_api_token(provided: str, expected: str) -> bool:
    return provided == expected


def verify_api_token_safe(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided, expected)


# --- REFERENCE FIX for password hashing -----------------------------------
def hash_password_safe(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-HMAC-SHA256. In production prefer argon2id or bcrypt."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 480_000)
    return f"pbkdf2_sha256$480000${salt.hex()}${digest.hex()}"


def sign_session(payload: str) -> str:
    """Signing key comes from config — see the hardcoded-credentials finding."""
    return hmac.new(JWT_SIGNING_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
