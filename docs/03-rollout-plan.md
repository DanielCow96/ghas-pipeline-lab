# Rollout plan: Veracode → GHAS

A template. Adapt the timings; keep the sequence. The ordering is the part that
matters, and the most common failure is doing phase 4 in week one.

## Principle: never run a new blocking gate cold

Rulesets support **`enforcement: "evaluate"`** — the rule reports what it *would*
have blocked without blocking anything. Every gate goes through evaluate mode
for at least two weeks before it goes active. This costs nothing, and it is the
difference between "we're enabling a security control" and "security broke the
build on a Friday", which is the story that follows you for years.

---

## Phase 0 — Baseline before you change anything (2 weeks)

You cannot prove a migration succeeded without a before.

- Export the current Veracode state: open findings **by CWE class**, by
  application, by severity. Not by finding ID — those do not survive.
- Record current remediation rates and mean age. These are your success metrics.
- Inventory: which repositories make up which Veracode application profile?
  This mapping does not exist in GHAS and you will need it forever. Build it now
  as a file in a repo, not a spreadsheet in someone's Drive.
- Count **active committers** in the last 90 days. That is your licence number.
  It is usually much smaller than headcount, and usually much smaller than
  finance assumes.

**Exit criteria:** a baseline document, and a repo→application map.

## Phase 1 — Turn on the free, non-blocking things (2 weeks)

Everything here is detection-only. Nothing can break a build.

- Dependency graph, Dependabot alerts, secret scanning across the estate.
- Code scanning in **default setup** on a pilot group of 5–10 repositories.
  Default setup is a two-click enable and needs no workflow file — use it for
  the pilot, move to advanced setup (a committed `codeql.yml`) when you need
  custom queries or a custom config.
- Do **not** enable push protection yet. Do **not** enable any gate yet.

**Exit criteria:** alert volumes known. If secret scanning returns hundreds of
historical alerts, enable **validity checks** — it will cut the actionable list
by an order of magnitude.

## Phase 2 — Push protection, estate-wide (1 week)

Out of sequence relative to the alerting work, deliberately: it is the highest
value-to-effort control in the product, it is preventive, and it generates
almost no false positives. It also produces an immediate, legible win to point
at while the slower work proceeds.

- Enable push protection everywhere.
- Configure bypass alerting to a channel security actually watches.
- Publish the leaked-credential runbook **before** you need it: revoke → rotate
  → assess exposure → then clean history.

**Exit criteria:** first blocked push, and a bypass reviewed within 24h.

## Phase 3 — Parallel run (one full release cycle, minimum)

Both tools running. This is the phase people try to skip, and it is the phase
that produces every piece of evidence you will need.

- Diff **by CWE class**, both directions, monthly. Two questions:
  - What did Veracode find that CodeQL did not? → coverage gap. Custom query,
    a second tool via SARIF, or documented accepted risk.
  - What did CodeQL find that Veracode did not? → your business case.
- Log every disagreement with a resolution. This document is what an auditor
  asks for, and it is what stops the decommission decision being re-litigated.
- Write custom queries for the gaps you find. This is when you will have the
  clearest possible view of what your company actually needs.

**Exit criteria:** a signed-off gap analysis with a named mitigation for each
gap, and a named owner for each item you accept.

## Phase 4 — Gates on, gradually (4–6 weeks)

Ordered by developer pain, lowest first:

1. **Dependency review** at `fail-on-severity: high`. Cheap, near-zero false
   positives, blocks the backlog from growing.
2. **Code scanning merge gate** on *new* alerts at critical only. Rulesets
   distinguish new from pre-existing — you are not asking anyone to fix history
   to merge a typo fix.
3. Tighten to high once mean-time-to-fix is stable.
4. **`scripts/policy_gate.py`** for SLA enforcement, last.

Each step: two weeks in `evaluate`, review what would have blocked, then
`active`. Announce every change a week ahead, in the channel developers read.

**Exit criteria:** gates active, and the build-break rate has returned to its
pre-gate baseline.

## Phase 5 — Decommission (2 weeks)

- Export everything from Veracode before the contract lapses: findings history,
  dismissal justifications, scan history, and any compliance attestations. **You
  will not get a second chance at this,** and "we accepted that risk in 2024,
  here is who signed it" is a question you will be asked after the tool is gone.
- Confirm the DAST / container / IaC gaps from `01-veracode-to-ghas-mapping.md`
  are covered by something with a name and an owner, not an intention.
- Keep the mapping document. It is the answer to "why did the numbers change?"
  for the next two years.

---

## The three things that sink these migrations

1. **Skipping the parallel run** because the contract renewal is in six weeks.
   The renewal date is a negotiating problem, not an engineering deadline. Pay
   for one more quarter rather than decommission blind.
2. **Forgetting DAST.** Static analysis replaces static analysis. Nobody
   notices the missing dynamic scanning until an auditor does.
3. **Turning on blocking gates to demonstrate progress.** Developer trust is
   spent once. Evaluate mode exists precisely so you never have to spend it.
