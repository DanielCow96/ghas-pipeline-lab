#!/usr/bin/env python3
"""Evaluate open GHAS code scanning alerts against the organisation's policy.

Runs in CI (see .github/workflows/security-policy-gate.yml) and locally:

    GH_TOKEN=ghp_xxx GITHUB_REPOSITORY=you/ghas-pipeline-lab python3 scripts/policy_gate.py

Exit code 0 = policy satisfied, 1 = policy violated. Standard library only, so
it runs unchanged on a GitHub Actions runner, a Jenkins agent or an Azure
DevOps pool — which is the point: the policy lives with the code, not in a
scanner's console.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ.get("GITHUB_REPOSITORY")
TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

SEVERITY_ORDER = ["note", "low", "medium", "moderate", "high", "critical", "error"]

BLOCK_AT = os.environ.get("BLOCK_AT_SEVERITY", "critical").lower()
SLA_DAYS = {
    "critical": int(os.environ.get("SLA_DAYS_CRITICAL", "7")),
    "high": int(os.environ.get("SLA_DAYS_HIGH", "30")),
    "medium": int(os.environ.get("SLA_DAYS_MEDIUM", "90")),
    "moderate": int(os.environ.get("SLA_DAYS_MEDIUM", "90")),
}


def rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "note").lower())
    except ValueError:
        return 0


def fetch_alerts(state: str = "open") -> list[dict]:
    """Page through the code scanning alerts API."""
    alerts: list[dict] = []
    page = 1
    while True:
        url = f"{API}/repos/{REPO}/code-scanning/alerts?state={state}&per_page=100&page={page}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {TOKEN}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ghas-policy-gate",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print(
                    "Code scanning is not enabled on this repository yet, or the "
                    "token lacks security-events:read. Treating as no alerts.",
                    file=sys.stderr,
                )
                return []
            raise
        if not batch:
            break
        alerts.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return alerts


def severity_of(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    # security_severity_level is the CVSS-derived band and is the one to police.
    # `severity` is the SARIF level (error/warning/note) and is not comparable
    # across tools — a classic mistake when wiring a gate for the first time.
    return (rule.get("security_severity_level") or rule.get("severity") or "note").lower()


def age_days(alert: dict) -> int:
    created = alert.get("created_at")
    if not created:
        return 0
    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def main() -> int:
    if not REPO or not TOKEN:
        print("GITHUB_REPOSITORY and GH_TOKEN are required", file=sys.stderr)
        return 2

    alerts = fetch_alerts()

    blocking: list[dict] = []
    breached: list[dict] = []
    counts: dict[str, int] = {}

    for alert in alerts:
        sev = severity_of(alert)
        counts[sev] = counts.get(sev, 0) + 1

        if rank(sev) >= rank(BLOCK_AT):
            blocking.append(alert)

        limit = SLA_DAYS.get(sev)
        if limit is not None and age_days(alert) > limit:
            breached.append(alert)

    lines = ["## Security policy gate", ""]
    lines.append(f"Open code scanning alerts: **{len(alerts)}**")
    if counts:
        lines.append("")
        lines.append("| Severity | Open |")
        lines.append("| --- | --- |")
        for sev in reversed(SEVERITY_ORDER):
            if counts.get(sev):
                lines.append(f"| {sev} | {counts[sev]} |")

    def render(title: str, items: list[dict]) -> None:
        if not items:
            return
        lines.append("")
        lines.append(f"### {title}")
        for a in items[:25]:
            rule_id = (a.get("rule") or {}).get("id", "?")
            path = ((a.get("most_recent_instance") or {}).get("location") or {}).get("path", "?")
            lines.append(
                f"- [#{a.get('number')}]({a.get('html_url')}) `{rule_id}` "
                f"— {path} — {severity_of(a)} — {age_days(a)}d old"
            )
        if len(items) > 25:
            lines.append(f"- …and {len(items) - 25} more")

    render(f"Blocking — severity ≥ {BLOCK_AT}", blocking)
    render("Past remediation SLA", breached)

    summary = "\n".join(lines) + "\n"
    with open("policy-gate-summary.md", "w", encoding="utf-8") as fh:
        fh.write(summary)
    print(summary)

    if blocking or breached:
        print(
            f"POLICY FAILED: {len(blocking)} alert(s) at or above {BLOCK_AT}, "
            f"{len(breached)} past SLA.",
            file=sys.stderr,
        )
        return 1

    print("POLICY PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
