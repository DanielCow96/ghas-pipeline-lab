# Verified baseline

This is the real output of CodeQL against this source tree, not an estimate.
Keep it: a known-good baseline is how you tell "the scan found nothing" apart
from "the scan didn't run", which is the most dangerous failure mode in any
security pipeline and the one that silently survives a tool migration.

```
CodeQL CLI:   2.26.4 (codeql-bundle-linux64)
Suite:        codeql/python-queries:codeql-suites/python-security-extended.qls
Plus:         .github/codeql/custom-queries  (2 company policy rules)
Scanned:      10 Python files, 5 GitHub Actions workflow files
```

| Band | CVSS | Rule | Location |
| --- | --- | --- | --- |
| critical | 9.8 | `py/command-line-injection` | `app/reports.py:23` |
| critical | 9.8 | `py/unsafe-deserialization` | `app/importer.py:21` |
| critical | 9.1 | `py/full-ssrf` | `app/integrations.py:21` |
| critical | 9.1 | `py/xxe` | `app/importer.py:35` |
| high | 8.8 | `py/sql-injection` | `app/db.py:49` |
| high | 8.8 | `py/sql-injection` | `app/db.py:60` |
| high | 8.2 | `py/company/unsafe-xml-parser-configuration` | `app/importer.py:34` |
| high | 7.8 | `py/reflective-xss` | `app/main.py:37` |
| high | 7.5 | `py/clear-text-logging-sensitive-data` | `app/auth.py:30` |
| high | 7.5 | `py/path-injection` | `app/reports.py:33` |
| high | 7.5 | `py/request-without-cert-validation` | `app/integrations.py:29` |
| high | 7.5 | `py/weak-sensitive-data-hashing` | `app/auth.py:24` |
| high | 7.4 | `py/company/tls-verification-disabled` | `app/integrations.py:29` |
| medium | 6.1 | `py/log-injection` | `app/auth.py:30` |
| medium | 6.1 | `py/log-injection` | `app/auth.py:30` |
| medium | 5.4 | `py/stack-trace-exposure` | `app/main.py:69` |

**Total: 16 — 4 critical, 9 high, 3 medium.**

Both custom policy queries fire, which confirms the query pack resolves and the
`config-file` wiring is correct.

## What the scanner did NOT find — read this twice

The application contains **19** deliberately seeded weaknesses. CodeQL reported
16 alerts covering 13 distinct ones. The following were seeded and did not
appear in the CodeQL run:

| Seeded weakness | Location | Why it was missed |
| --- | --- | --- |
| Hardcoded credentials | `app/config.py:19,26` | CodeQL's `py/hardcoded-credentials` requires the value to flow into an authentication sink it recognises. A constant that is only string-formatted into a DSN doesn't match. **Bandit catches this** (B105) — which is exactly why `third-party-sarif.yml` exists. |
| Insecure temporary file | `app/reports.py:41` | **Neither tool finds it.** CodeQL wants a specific unsafe API; Bandit's B108 only matches a literal `"/tmp"` string, and this code calls `tempfile.gettempdir()`. A predictable filename in a shared temp directory is a real symlink-attack vector and both scanners walk straight past it. |
| Incomplete URL sanitisation | `app/integrations.py:47` | The substring check is a real bypass, but the taint doesn't reach a sink the query models. A human reviewing `if host in url` spots it instantly. |
| Timing-unsafe token comparison | `app/auth.py:52` | Not modelled by the default Python suite at all, and not by Bandit either. |
| Binds all interfaces | `app/main.py:96` | Under `__main__`. **Bandit catches it** (B104). |

## Bandit baseline — and three verified false positives

`bandit 1.7.8 -r app` reports **17 findings: 3 high, 6 medium, 8 low**. CI is
green at the same time (`ruff` clean, 9 tests passing), which is the point of
Module 3: functional health and security health are separate signals.

Bandit covers two things CodeQL missed — `B105` hardcoded password
(`app/config.py:13`) and `B104` bind-all-interfaces (`app/main.py:100`). It
also produces **three false positives, all on the deliberately-correct
reference functions**:

| Bandit finding | Location | Why it is wrong |
| --- | --- | --- |
| `B608` SQL injection | `app/db.py:86` | `list_orders_sorted_safe` — the column name is checked against `_ALLOWED_SORT_COLUMNS` two lines above. Bandit sees an f-string in a query and stops there. |
| `B320` unsafe XML parse | `app/importer.py:62` | `parse_partner_feed_safe` — the parser is constructed with `resolve_entities=False, load_dtd=False, no_network=True`. Bandit flags `etree.fromstring` regardless of parser configuration. |
| `B603`/`B607` subprocess | `app/reports.py:51` | `convert_report_to_pdf_safe` — argument list, no shell, path validated against the report root. |

Note *why* all three are wrong in the same way: **Bandit pattern-matches, CodeQL
follows data flow.** Bandit cannot see the validation, because it does not model
what happens between two lines of code. This is the single most important
technical difference between rule-based linters and dataflow engines, and it is
the reason your false-positive rate will fall when you move injection-class
rules onto CodeQL — the argument to make when a developer says "the new tool is
just as noisy".

It is also a warning about `third-party-sarif.yml`: bolt on a linter carelessly
and you re-import the noise you just escaped. Scope each tool to the rule
classes it is actually good at.

**This table is the most useful thing in the lab.** Five real weaknesses, none
reported. Two are caught by a second tool, three by nothing but a human.

Carry three conclusions into your new role:

1. **No single scanner is a control.** Coverage is a portfolio: CodeQL for
   dataflow, a linter for local patterns, review for logic. Anyone who tells
   you a clean scan means secure code is selling something.
2. **A clean scan is not evidence of absence.** When you replace Veracode and
   the alert count drops, that is not automatically an improvement. It could
   be coverage loss. Diff by CWE class, both directions.
3. **Coverage gaps are where custom queries earn their keep.** The timing-unsafe
   comparison and the substring allowlist are both perfectly expressible in
   CodeQL. Nobody ships them because they are company-specific. That is your job now.

## Regenerate this baseline

```bash
./scripts/run-codeql-local.sh
```

Re-run it after every change to `codeql-config.yml` and diff. A tuning change
that quietly drops eight alerts is the thing you most need to catch, and the
Security tab will not tell you.
