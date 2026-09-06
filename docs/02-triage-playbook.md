# Triage playbook

The part of the job that is actually the job. Tooling is a weekend; triage is
every week for years.

## The daily loop (20 minutes)

1. **New criticals and highs since yesterday.** Nothing else counts as urgent.
2. For each: decide *reachable in production?* before anything else. An
   unreachable critical outranks nothing.
3. Assign or fix. An alert with no owner is not being worked on, whatever the
   dashboard says.
4. Check push-protection bypasses from the last 24h. Every bypass is either a
   near-miss you should learn from or a leaked credential you must rotate.

## The weekly loop (60 minutes)

1. Run `./scripts/ghas-alert-report.sh`. Compare with last week.
2. Anything past SLA → escalate to the owning team's lead, not the developer.
3. Review every dismissal made this week. Comment quality is the health metric.
4. One tuning action: a `paths-ignore` entry, a query removed, a custom rule.
   One per week compounds; a quarterly tuning project never happens.

## Deciding on a single alert

Work through it in this order. Stop at the first line that resolves it.

1. **Is the sink real?** Follow the CodeQL path to the last node. If the sink
   is a logging call in a test harness, you are done — dismiss, used in tests,
   and add the path to `paths-ignore` so it never recurs.
2. **Is the source attacker-controlled?** A path from a config file read at
   boot by a root-owned process is not the same as a path from an HTTP
   parameter. CodeQL will show you the source node; read it, don't assume.
3. **Is there a sanitiser the tool didn't model?** This is where most true
   false positives live. If you find one, the correct output is not a
   dismissal — it is a **model**: a `sanitizer` added to a custom query, or a
   MaD (Models-as-Data) entry. Fixing it once fixes it everywhere. Dismissing
   it fixes it once and guarantees you do it again next quarter.
4. **What is the blast radius if it is real?** Severity from the tool is CVSS
   in the abstract. You know whether that service is internet-facing.
5. **Only now:** fix, or accept with a name and a date on it.

## Rules for dismissal comments

A dismissal comment is read by an auditor who was not in the room, eighteen
months later, possibly after an incident. Write for that reader.

Bad: *"not exploitable"*
Bad: *"false positive"*
Bad: *"discussed with team, fine"*

Good: *"Sink is `subprocess.run` with a list argument, not a shell string —
CodeQL models the wrapper in `utils/exec.py:22` as shell-invoking, which it is
not. Modelling fix tracked in SEC-2210; dismissing this instance. — dan, 2026-09-05"*

Good: *"Reachable only from the internal admin console, which requires mTLS +
SSO. Accepted by J. Tan (app owner) for this release; fix scheduled in
SEC-1188 for Q1. Review 2027-01-15."*

The test: **does the comment let a stranger re-derive your decision without
asking you?** If not, rewrite it.

## Metrics that mean something

| Metric | Why | Target shape |
| --- | --- | --- |
| Mean age of open critical/high | The only real measure of whether the programme functions | Falling |
| % of alerts past SLA | Where the programme is actually failing | → 0 |
| Fixed : dismissed ratio | Rising dismissals = miscalibrated rules, or fatigue | Stable or improving |
| Dismissals with no comment | Process discipline | 0, always |
| Push-protection blocks | Prevention working | Non-zero is good news |
| Mean time from alert to PR | Developer friction | Falling |

**Not** a metric: total open alerts. It goes up when you enable a new query and
down when you disable one, and it tells you nothing about risk. Every security
programme that reports total open alerts to executives eventually gets pressured
into tuning them away. Report the age of criticals instead — it cannot be gamed
without actually fixing something.

## Anti-patterns worth naming out loud

- **Bulk dismissal on tool onboarding.** The temptation on day one is to
  dismiss 400 legacy alerts to get to zero. Do not. Filter the *view* by
  "introduced since <date>" instead, and burn the backlog down deliberately.
  Bulk dismissal destroys the record, and the record is the asset.
- **Tuning to hit a number.** If someone asks you to get the count under 50,
  the honest answer is which queries you'd have to disable and what that
  costs in coverage. Put it in writing.
- **Security owning remediation.** You own the queue, the rules and the
  standard. Developers own the fix. The moment security starts writing the
  patches, the queue becomes your backlog and it never shrinks.
- **Treating a scanner as a control.** See `docs/07-verified-baseline.md`:
  five seeded flaws that no scanner reported.
