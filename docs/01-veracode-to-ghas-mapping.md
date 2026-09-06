# Veracode → GHAS: what maps, what doesn't

Fill in the right-hand column for your own estate. The gaps are the deliverable —
your management will accept "we lose X, here is the mitigation" far more readily
than a comparison chart that claims parity.

## Product shape

GitHub Advanced Security is no longer sold as one bundle. Since 2025 it is two
SKUs, purchasable separately:

| SKU | Contains |
| --- | --- |
| **GitHub Secret Protection** | Secret scanning, push protection, validity checks, secret risk assessment |
| **GitHub Code Security** | Code scanning (CodeQL), Copilot Autofix, security campaigns, premium Dependabot features, dependency review |

Licensing is **per unique active committer** — anyone who pushed a commit in the
last 90 days to a repository with the feature enabled. One person counts once,
however many repositories they touch. This is a genuinely different cost model
from Veracode's per-application or scan-volume licensing, and it changes the
economics: adding repositories is free, adding developers is not. **Budget from
your committer count, not your application count** — the first draft of every
migration budget gets this backwards.

On **public** repositories all of it is free.

## Capability mapping

| Veracode capability | GHAS equivalent | Notes / gap |
| --- | --- | --- |
| Static Analysis (policy scan) | CodeQL code scanning | CodeQL analyses source, Veracode analyses compiled binaries. Consequence: CodeQL needs a working build for compiled languages, and cannot scan a third-party binary you don't have source for. Check for any app where you scan a vendor artefact. |
| Static Analysis (sandbox scan) | CodeQL on a PR / branch | Same engine, different ref. No separate "sandbox" concept — the branch *is* the sandbox. |
| Software Composition Analysis | Dependabot + dependency review | Advisory sources differ. Expect 10–20% delta. Dependency review is the blocking gate; Dependabot alerts is the backlog view. |
| SCA reachability analysis | Partially — Dependabot does not do full reachability | **GAP.** If you rely on Veracode reachability to suppress noise, plan for a higher raw alert count, or pair with a third-party tool via SARIF. |
| Dynamic Analysis (DAST) | None | **GAP — the big one.** GHAS has no DAST. Keep Veracode DAST, or move to OWASP ZAP / Burp in CI and upload SARIF. Decide before cutover; this is the most common thing a migration forgets. |
| Software Bill of Materials | Dependency graph export / CycloneDX | See `ci.yml`. GitHub exports SPDX via API; CycloneDX via tooling. |
| Manual Penetration Testing | None | Procure separately. Not a tooling decision. |
| Container / image scanning | None natively | **GAP.** Use Trivy/Grype → SARIF (`third-party-sarif.yml` shows the pattern). |
| IaC scanning | None natively | **GAP.** Checkov/tfsec → SARIF. |
| Security Labs (training) | GitHub Skills / Secure Code Game | Weaker. If training completion is a compliance control for you, this is a real gap. |
| Policy management | Rulesets + `scripts/policy_gate.py` | GHAS has no policy *object*. You express policy as rulesets plus code. More flexible, less turnkey — someone has to own it. That someone is you. |
| Application inventory & business criticality | None | **GAP.** No "application" concept; repositories are the unit. Build your own mapping (repo topics, a CODEOWNERS-adjacent inventory file, or your CMDB). Do this in week one. |
| Grace periods / remediation SLAs | `scripts/policy_gate.py` | Not built in. The script in this repo is the pattern. |
| Executive reporting | Security Overview | Good dashboards, weak export. Expect to build reporting on the REST/GraphQL API. `scripts/ghas-alert-report.sh` is the starting point. |
| Findings API | REST code-scanning / dependabot / secret-scanning APIs | Better than Veracode's, honestly. Everything in the UI is in the API. |

## Things GHAS does that Veracode does not

Worth listing explicitly, because migrations are usually pitched defensively
and this is the actual upside:

- **Push protection.** Prevention, not detection, at the git layer.
- **Custom queries.** Your policy becomes an executable rule. See Module 6.
- **Data-flow paths in the alert.** Cuts triage arguments to seconds.
- **Evaluate mode on rulesets.** Measure a gate's blast radius before enabling it.
- **Copilot Autofix.** A suggested patch attached to the alert.
- **Security campaigns.** Bulk-assign a class of alerts to teams with a deadline
  and track burn-down (requires Code Security licensing).
- **It lives where the developers already are.** The single largest driver of
  remediation rate is not scan quality — it is whether a developer has to open
  a second tool. This is the argument that wins the business case.

## The honest summary for your manager

> GHAS replaces Veracode's static analysis and SCA with tighter developer
> integration, a lower per-repository cost, and the ability to encode our own
> policy as scanner rules. It does **not** replace Veracode's DAST, container
> or IaC scanning, and it has no application-inventory concept — we will need
> to cover those separately before we can decommission. Recommended sequence:
> run both in parallel for one full release cycle, diff by CWE class, and only
> then cancel.
