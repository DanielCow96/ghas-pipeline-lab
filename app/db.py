"""Data access layer.

LAB NOTE: deliberate weaknesses. Expected CodeQL rule: py/sql-injection (CWE-89).
Uses sqlite3 so the lab runs with no external database.
"""

import sqlite3
from typing import Any

DB_PATH = "orders.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema() -> None:
    with get_connection() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS orders (
                   id INTEGER PRIMARY KEY,
                   customer TEXT NOT NULL,
                   region TEXT NOT NULL,
                   total_cents INTEGER NOT NULL,
                   status TEXT NOT NULL
               )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   username TEXT PRIMARY KEY,
                   password_hash TEXT NOT NULL,
                   role TEXT NOT NULL
               )"""
        )


# --- VULN 3: SQL injection via string interpolation (CWE-89) ---------------
# CodeQL: py/sql-injection
def find_orders_by_customer(customer: str) -> list[dict[str, Any]]:
    """Look up orders for a customer.

    The customer name is interpolated straight into the statement, so a value
    like  ' OR '1'='1  returns every row in the table.
    """
    query = f"SELECT id, customer, region, total_cents, status FROM orders WHERE customer = '{customer}'"  # noqa: S608
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


# --- VULN 4: SQL injection in a sort parameter (CWE-89) --------------------
# CodeQL: py/sql-injection
# Sort/filter parameters are the classic blind spot: they cannot be
# parameterised, so they must be validated against an allowlist instead.
def list_orders_sorted(sort_column: str, direction: str = "ASC") -> list[dict[str, Any]]:
    query = f"SELECT * FROM orders ORDER BY {sort_column} {direction}"  # noqa: S608
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


# --- REFERENCE FIX: the same query done safely -----------------------------
# Keep this in the repo. During triage you will be asked "what does the fix
# look like?" — this is the answer for the interpolation cases above.
_ALLOWED_SORT_COLUMNS = {"id", "customer", "region", "total_cents", "status"}


def find_orders_by_customer_safe(customer: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, customer, region, total_cents, status FROM orders WHERE customer = ?",
            (customer,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_orders_sorted_safe(sort_column: str, direction: str = "ASC") -> list[dict[str, Any]]:
    if sort_column not in _ALLOWED_SORT_COLUMNS:
        raise ValueError(f"unsupported sort column: {sort_column}")
    if direction.upper() not in {"ASC", "DESC"}:
        raise ValueError("direction must be ASC or DESC")
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM orders ORDER BY {sort_column} {direction.upper()}"  # noqa: S608
        ).fetchall()
    return [dict(r) for r in rows]
