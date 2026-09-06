# GHAS Pipeline Lab

A deliberately vulnerable Python service, a complete CI/CD pipeline, and the
operational material for running GitHub Advanced Security as a security handler.

Built as a training environment for taking over CI/CD security during a
**Veracode → GHAS migration**.

> ⚠️ **The application in `app/` is intentionally insecure.** It exists to
> generate findings. Never deploy it, never copy from it, and keep the
> repository clearly labelled. The *safe* variants (`*_safe`) next to each flaw
> are the ones worth reading.

---

## Start here

| If you want to… | Go to |
| --- | --- |
| Do the course | [`docs/00-lab-guide.md`](docs/00-lab-guide.md) — nine modules |
| Know what GHAS replaces and what it doesn't | [`docs/01-veracode-to-ghas-mapping.md`](docs/01-veracode-to-ghas-mapping.md) |
| Learn the day-to-day job | [`docs/02-triage-playbook.md`](docs/02-triage-playbook.md) |
| Plan the actual migration | [`docs/03-rollout-plan.md`](docs/03-rollout-plan.md) |
| Run GHAS from Jenkins or Azure DevOps | [`docs/05-portable-ci.md`](docs/05-portable-ci.md) |
| See real, verified scan results | [`docs/07-verified-baseline.md`](docs/07-verified-baseline.md) |

## Push it and go

Create an empty **public** repository on GitHub, then:

```bash
git init -b main
git add .
git commit -m "Initial lab: deliberately vulnerable orders API with GHAS pipeline"
git remote add origin https://github.com/<you>/ghas-pipeline-lab.git
git push -u origin main
```

Then **Settings → Advanced Security** and enable: Dependabot alerts, Dependabot
security updates, secret scanning, push protection, code scanning (advanced),
private vulnerability reporting.

**Public, not private, and this matters.** Code scanning, secret scanning, push
protection and dependency review are free on public repositories — the same
engines an enterprise pays for. GitHub Student gives you Pro, and Pro does *not*
include Advanced Security on private repos, so a private lab would leave the
Security tab dark. Public repo, nothing real in it.

## What's in here

```
app/                     19 seeded weaknesses + a safe variant of each
tests/                   9 passing tests, incl. a working SQLi exploit proof
.github/workflows/
  ci.yml                 build, lint, test, SBOM — the non-security baseline
  codeql.yml             SAST on PR, push and weekly cron
  dependency-review.yml  blocking SCA gate on pull requests
  third-party-sarif.yml  Bandit + pip-audit → SARIF → Security tab
  security-policy-gate.yml   SLA and aggregate policy enforcement
.github/codeql/
  codeql-config.yml      query selection and scope, reviewable as code
  custom-queries/        two compiled, verified company-policy CodeQL rules
policy/                  repository ruleset — the real merge gate
scripts/
  run-codeql-local.sh    the portable Jenkins/ADO integration, and your dev loop
  policy_gate.py         SLA enforcement, stdlib only, runs on any CI
  ghas-alert-report.sh   the weekly report you will actually be asked for
docs/                    the course and the migration material
```

## Verified, not asserted

Everything below was executed against this source tree before it was written
down — see [`docs/07-verified-baseline.md`](docs/07-verified-baseline.md):

- **CodeQL 2.26.4**, `python-security-extended` + both custom queries:
  **16 alerts — 4 critical, 9 high, 3 medium**. Both custom policy rules fire.
- **Bandit 1.7.8**: 17 findings — including **three false positives on the
  deliberately-correct reference functions**, which is the clearest available
  demonstration of pattern-matching versus dataflow analysis.
- **CI green at the same time**: `ruff` clean, 9/9 tests passing.
- **Five seeded weaknesses that neither scanner reported.** That table is the
  most useful thing in the repository.

## The four ideas worth taking to work

1. **GitHub is the findings platform; CI is just where scanners run.** SARIF is
   the contract. Once that lands, "we're on Jenkins" stops blocking meetings.
2. **Never enable a blocking gate cold.** Rulesets have an `evaluate` mode that
   reports what *would* have been blocked. Two weeks in evaluate, then active.
   Developer trust is spent once.
3. **A false positive is a modelling bug, not a dismissal.** Dismissing fixes
   one alert; modelling the sanitiser fixes the class.
4. **Custom queries are the actual business case.** Every company has policy
   rules no vendor ships. In a wiki they are decoration; in CodeQL they block
   the merge.
