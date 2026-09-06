# The lab: nine modules

Each module is a sitting of 30–90 minutes. Do them in order — later ones
depend on state you create earlier. Every module ends with **evidence**: a
screenshot, a URL, or a file. Keep those; they become the artefacts you show
your company when they ask what the migration plan is based on.

Set-up assumption: you push this repository to your **personal GitHub account
as a PUBLIC repository**. That is not a compromise — on public repositories,
code scanning, secret scanning, push protection and dependency review are free
and are the same engines an enterprise pays for. A GitHub Student account gives
you GitHub Pro, but Pro does **not** include Advanced Security on private
repositories, so a private lab repo would leave you with the Security tab
switched off. Use public, and never put anything real in it.

---

## Module 0 — Stand it up

1. Create an empty **public** repository on GitHub, e.g. `ghas-pipeline-lab`.
   Do not initialise it with a README.
2. From this directory:

   ```bash
   git init -b main
   git add .
   git commit -m "Initial lab: deliberately vulnerable orders API with GHAS pipeline"
   git remote add origin https://github.com/<you>/ghas-pipeline-lab.git
   git push -u origin main
   ```

3. **Settings → Advanced Security.** Turn on, in this order:
   - Dependency graph (usually already on for public repos)
   - Dependabot alerts
   - Dependabot security updates
   - Secret scanning
   - Push protection
   - Code scanning → *Advanced* (it will detect `.github/workflows/codeql.yml`)
   - Private vulnerability reporting

4. Watch the Actions tab. Five workflows should run. Expect CI to pass and the
   security workflows to find things.

**Evidence:** the Security tab with a non-zero alert count.

**Reflect:** you just did in four minutes what a Veracode onboarding does with
an application profile, a team assignment and a policy attachment. Note what
you *did not* get: no application owner, no business criticality, no policy
object. GHAS has no built-in concept of "application" — repositories are the
unit. Holding the mapping from *application* to *repositories* is now your job,
and there is no field for it. Most teams keep it in a `topics` label or a
`CODEOWNERS`-adjacent inventory file. Decide this early; retrofitting it across
300 repositories is miserable.

---

## Module 1 — Read the first scan honestly

Open **Security → Code scanning alerts**. You should see **16 CodeQL alerts —
4 critical, 9 high, 3 medium** — plus a set from Bandit. That is not an
estimate: `docs/07-verified-baseline.md` is the actual output of CodeQL 2.26.4
running `python-security-extended` against this exact source tree. If your
numbers differ materially, something is misconfigured — check the
`config-file` path in `codeql.yml` first.

Do these, in the UI:

1. Filter by `Tool: CodeQL` then `Tool: bandit`. Notice the overlap — both flag
   the `subprocess` call. **This is the migration problem in miniature.**
   Two tools, one bug, two alerts, two triage decisions. Decide now which tool
   is authoritative for which rule class, and write it down. (Suggested answer
   for Python: CodeQL for anything dataflow-dependent — injection, SSRF, XSS;
   Bandit for local pattern checks CodeQL does not ship, e.g. `assert` in
   production paths. Do not run both for the same rule class.)
2. Open the `py/sql-injection` alert. Click through the **data flow path**.
   Follow it from the FastAPI parameter to the `execute` call.
3. Open the two `py/log-injection` alerts on `app/auth.py:30`. **They are on the
   same line.** One line of code, two alerts, because two tainted values reach
   the same sink. Your queue metrics will count that as two. Veracode would
   likely count it as one. This is why alert *counts* never survive a tool
   migration and CWE-class counts do.
4. Compare `py/request-without-cert-validation` (CodeQL's own, 7.5) with
   `py/company/tls-verification-disabled` (our custom rule, 7.4). Same line,
   `app/integrations.py:29`. You have just created a duplicate. Deciding what
   to do about it is Module 6's real exercise — the answer is usually to delete
   your rule when the vendor ships an equivalent, and the discipline is to
   check before you write one.

**Evidence:** write down, for five alerts, which of these three they are —
*true positive worth fixing*, *true positive not worth fixing*, *false
positive*. You will check yourself in Module 2.

**The one thing to internalise:** CodeQL's value is the *path*, not the alert.
Veracode gives you a finding with a location; CodeQL shows you the source, the
sink, and every step between. When a developer says "that input is already
validated", the path is how you settle it in thirty seconds instead of a
meeting.

---

## Module 2 — Triage like it is your job

Work the queue. For each alert take exactly one of four actions:

| Action | When | How |
| --- | --- | --- |
| Fix | The flaw is real and reachable | Open a PR; the alert closes itself on merge |
| Dismiss — false positive | The path does not exist | Requires a comment explaining why |
| Dismiss — used in tests | Non-production code | Better: exclude via `paths-ignore` |
| Dismiss — won't fix | Risk accepted by a named human | Comment must carry a ticket ref and review date |

Do all four at least once. Specifically:

- **Fix** `py/sql-injection` in `find_orders_by_customer` — the safe version is
  already in `app/db.py` as `find_orders_by_customer_safe`. Open a branch, make
  the change, open a PR, watch the alert move to "Fixed" on merge.
- **Dismiss as won't fix** `py/stack-trace-exposure` (`app/main.py:69`), with a
  comment like: *"Endpoint is internal-only behind mTLS; traces are required
  for support triage. Accepted, SEC-1041, review 2027-03-01."* Notice how much
  weaker that justification looks written down than it sounds in a meeting —
  that discomfort is the control working.
- Try **Copilot Autofix** on one alert (public repos get it free). Read the
  suggested patch critically — then look at whether it fixed the *class* or
  the *instance*. Autofix is excellent at instances. Classes are still yours.

Then run:

```bash
./scripts/ghas-alert-report.sh <you>/ghas-pipeline-lab
```

Look at the "dismissed with NO COMMENT" line. If it is not empty, you have
just demonstrated the failure mode that kills these programmes.

**Evidence:** the alert report output, before and after.

---

## Module 3 — Make it block

An alert nobody must act on is a newsletter. Turn it into a gate.

1. Apply the ruleset:

   ```bash
   gh api -X POST /repos/<you>/ghas-pipeline-lab/rulesets \
     --input policy/ruleset-main-protection.json
   ```

   (Or Settings → Rules → Rulesets → New ruleset, and mirror the JSON.)

2. Create a branch that introduces a *new* high-severity flaw — copy the
   `verify=False` call into a second function — and open a PR.
3. Watch the merge button turn red, and read *why*: the `code_scanning` rule
   in the ruleset, not the workflow.

Now do the important part: set the ruleset `enforcement` to `evaluate`, push
the same PR again, and see it report without blocking.

**This is the single most useful GHAS feature for a migration and almost
nobody uses it.** You can run every rule in evaluate mode across the whole
organisation, collect two weeks of "what would have been blocked", and walk
into the go/no-go meeting with real numbers instead of a promise. Veracode has
no equivalent that costs you nothing.

**Evidence:** a screenshot of a blocked merge, and the same PR passing under
evaluate mode.

---

## Module 4 — Dependencies, the boring half that actually gets exploited

1. Open **Security → Dependabot alerts**. `requirements.txt` is pinned to
   versions with real advisories; each line comments the GHSA to expect.
2. Let Dependabot open its PRs (or trigger from the Insights → Dependency graph
   → Dependabot tab). Note the **grouping** configured in `.github/dependabot.yml` —
   one PR for routine bumps, separate PRs for security ones.
3. Open a PR that adds a knowingly-vulnerable package to `requirements.txt`,
   e.g. `pyyaml==5.1`. Watch **dependency review** fail the check and comment
   on the PR with the advisory.
4. Compare the three sources you now have: Dependabot alerts, dependency
   review, and `pip-audit` in `third-party-sarif.yml`. They will not agree
   perfectly. Work out why. (Hint: transitive resolution, and the difference
   between "in the manifest" and "in the lockfile".)

**The migration point:** Veracode SCA and GitHub's advisory database draw from
overlapping but different sources. During cutover, run both for one cycle and
diff, per package, not per finding. Expect 10–20% disagreement and expect most
of it to be reachability and transitive-depth methodology, not one tool being
wrong. Document the delta before you decommission — it is the first thing an
auditor will ask about.

---

## Module 5 — Secrets, and the only control that prevents rather than detects

Secret scanning detects. **Push protection prevents.** It is the highest-value,
lowest-effort control in the whole product, and it is free on public repos.

Do this exercise deliberately — the repository ships with no secrets in it,
because the lesson is the block, not the leak:

1. Confirm push protection is on (Settings → Advanced Security).
2. Create a file containing a *self-generated, immediately-revoked* token from
   a service you control — or, safest, use GitHub's own documented test
   pattern. Never commit a live credential to practise, and never use a
   colleague's.
3. Commit and push. The push is **rejected at the git layer**, before the
   commit reaches GitHub, with a link explaining what was found.
4. Walk the bypass flow: push protection lets a developer bypass with a
   reason ("used in tests", "false positive", "will fix later"). Every bypass
   is logged and can raise an alert to the security team. Find that setting.

Then answer, in writing: **if a secret does land, what is your runbook?**
The correct order is *revoke → rotate → assess exposure window → then* clean
history. Cleaning history first is the classic rookie sequence, and it wastes
the only minutes that matter.

Also enable **validity checks**: GitHub will tell you whether a leaked token
is still live. That single flag turns a queue of 400 historical secret alerts
into a list of 6 that need action today.

**Evidence:** the rejected push output.

---

## Module 6 — Write a rule your company actually needs

This is where you stop being a tool operator and start being a security
engineer, and it is the capability Veracode does not give you at all.

`.github/codeql/custom-queries/` contains two working queries, both compiled
and verified:

- `TlsVerificationDisabled.ql` — policy CRY-002, `verify=False`
- `UnsafeXmlParserConfiguration.ql` — policy XML-001, unsafe lxml parser

Read them. They are short on purpose. Then:

1. Install the CodeQL CLI **bundle** (not the bare CLI — the bundle ships the
   query packs): https://github.com/github/codeql-action/releases/latest
2. Run `./scripts/run-codeql-local.sh` and confirm your two policy alerts appear.
3. Write a third. Suggested: flag any `requests` call without a `timeout`
   argument (a real availability control, and a rule no vendor ships).
   Start from `TlsVerificationDisabled.ql` and change the `where` clause to
   `not exists(call.getArgByName("timeout"))`.
4. Compile it: `codeql query compile YourQuery.ql`. Iterate until it passes.

**Why this matters more than it looks.** Every organisation has a dozen rules
that are policy rather than vulnerability: "no HTTP to internal services",
"all outbound calls have timeouts", "no direct use of the legacy crypto
wrapper". With a vendor scanner these live in a wiki nobody reads. With CodeQL
they live in the pipeline and block the merge. When you are asked to justify
the migration in business terms, this — not scan quality — is the argument.

---

## Module 7 — Make it work without GitHub Actions

Your company may run Jenkins or Azure DevOps. GHAS still works; the wiring
changes. See `docs/05-portable-ci.md` for the full pattern, then:

1. Run `./scripts/run-codeql-local.sh` — that is the whole Jenkins stage.
2. Run it with `--upload` against your lab repo and confirm the results appear
   in the Security tab as if Actions had produced them.

The mental model to keep: **GitHub is the findings platform; the CI system is
just a place to run scanners.** SARIF is the contract between them. Once you
have internalised that, "we're on Jenkins" stops being a blocker in every
meeting.

---

## Module 8 — Operate it, and plan the cutover

1. Read `docs/01-veracode-to-ghas-mapping.md` and fill in the gap column for
   *your* company — the answers depend on which Veracode modules you actually
   licensed.
2. Read `docs/03-rollout-plan.md` and adapt the phasing.
3. Set up the weekly report as a scheduled job and send yourself the output.
4. Write the one-page brief your manager will ask for: what changes for
   developers, what changes for the security team, what capability is lost,
   and what it costs.

**Evidence:** the brief. If you can write that page from your own lab
experience rather than from a vendor comparison table, you are ready to run
the transition.
