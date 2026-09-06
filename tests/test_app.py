"""Tests for the lab application.

These exist so CI is a real build, not a stub — and so you can watch a
security gate fail a pull request while the functional tests stay green. That
separation is the whole argument for putting security checks in the pipeline
rather than in a quarterly report.
"""

import sqlite3

import pytest

from app import auth, db, importer, reports
from app import integrations


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_schema()
    with db.get_connection() as conn:
        conn.execute(
            "INSERT INTO orders (id, customer, region, total_cents, status) VALUES (?,?,?,?,?)",
            (1, "acme", "APAC", 12500, "shipped"),
        )
        conn.execute(
            "INSERT INTO orders (id, customer, region, total_cents, status) VALUES (?,?,?,?,?)",
            (2, "globex", "EMEA", 4200, "pending"),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ("alice", auth.hash_password("hunter2"), "admin"),
        )
    yield


def test_find_orders_returns_matching_customer():
    assert len(db.find_orders_by_customer("acme")) == 1


def test_sql_injection_is_actually_exploitable():
    """Proof the finding is real, not theoretical.

    When you triage the py/sql-injection alert, this is the evidence you
    attach: a test that demonstrates the impact. A reviewer who can run this
    stops arguing about whether the alert matters.
    """
    payload = "nobody' OR '1'='1"
    rows = db.find_orders_by_customer(payload)
    assert len(rows) == 2, "expected the injection to return every row"


def test_safe_variant_is_not_exploitable():
    payload = "nobody' OR '1'='1"
    assert db.find_orders_by_customer_safe(payload) == []


def test_authenticate_accepts_valid_credentials():
    assert auth.authenticate("alice", "hunter2")["role"] == "admin"


def test_authenticate_rejects_bad_password():
    assert auth.authenticate("alice", "wrong") is None


def test_path_traversal_is_blocked_by_safe_variant():
    with pytest.raises(ValueError):
        reports._resolve_inside_report_root("../../etc/passwd")


def test_yaml_safe_load_rejects_python_object_tags():
    document = "!!python/object/apply:os.system ['echo pwned']"
    with pytest.raises(Exception):
        importer.load_import_profile_safe(document)


def test_sorted_listing_allowlist():
    with pytest.raises(ValueError):
        db.list_orders_sorted_safe("id; DROP TABLE orders")
    assert len(db.list_orders_sorted_safe("total_cents", "DESC")) == 2


def test_schema_exists():
    with db.get_connection() as conn:
        tables = {
            r["name"]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert {"orders", "users"} <= tables
    assert isinstance(db.get_connection(), sqlite3.Connection)


def test_fetch_partner_document_allows_https_allowlisted_host(monkeypatch):
    class _Response:
        text = "ok"

    called = {}

    def _fake_get(url, timeout, allow_redirects):
        called["url"] = url
        called["timeout"] = timeout
        called["allow_redirects"] = allow_redirects
        return _Response()

    monkeypatch.setattr(integrations.requests, "get", _fake_get)

    body = integrations.fetch_partner_document("https://partner.example.com/doc")
    assert body == "ok"
    assert called == {
        "url": "https://partner.example.com/doc",
        "timeout": integrations.TIMEOUT,
        "allow_redirects": False,
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://partner.example.com/doc",
        "https://attacker.example.com/doc",
    ],
)
def test_fetch_partner_document_rejects_non_allowlisted_urls(url):
    with pytest.raises(ValueError):
        integrations.fetch_partner_document(url)
