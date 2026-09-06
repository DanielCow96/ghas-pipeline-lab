# Security policy

> **This repository is a training lab.** The application in `app/` contains
> intentional vulnerabilities and must never be deployed or reused. Do not
> report its findings as if they were a real product vulnerability.

## Reporting a vulnerability

Use **private vulnerability reporting** (Security tab → Report a vulnerability)
rather than opening a public issue. Private reporting is free on every public
repository and creates a draft advisory that becomes the coordination workspace:
a private fork for the fix, a CVE request, and a published GitHub Security
Advisory when you are ready.

Enable it under *Settings → Advanced Security → Private vulnerability reporting*.

## Remediation SLAs

Measured from alert creation, enforced by `scripts/policy_gate.py`.

| Severity | Fix by | Merge blocked? |
| --- | --- | --- |
| Critical | 7 days | Yes — new alerts block the PR |
| High | 30 days | Yes — new alerts block the PR |
| Medium | 90 days | No, tracked |
| Low / Note | Best effort | No |

Severity means **`security_severity_level`** (the CVSS-derived band), not the
SARIF `level`. Tools disagree about `level`; they broadly agree about CVSS.

## Dismissing an alert

Every dismissal needs a reason and a comment. The three reasons GitHub offers
map to real decisions:

- **False positive** — the code path does not exist as the tool describes.
  Comment must say *why*. If the tool is wrong repeatedly for the same rule,
  that is a tuning task, not eighteen dismissals.
- **Used in tests** — the code is not reachable in production. Prefer fixing
  this with `paths-ignore` in the CodeQL config so it never becomes an alert.
- **Won't fix (risk accepted)** — a human accepted the risk. Comment must
  reference the ticket and the review date.

Dismissals are auditable via the API and are reversible. "Delete alert" is not
available for code scanning by design — the record survives.

## Secrets

If a secret is committed, rotating it comes first and removing it from history
comes second. History rewriting does not un-leak a credential: assume anything
pushed to a public repository was scraped within seconds.
