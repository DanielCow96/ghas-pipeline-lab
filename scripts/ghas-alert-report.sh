#!/usr/bin/env bash
#
# The reporting layer. During a Veracode→GHAS migration this is the script you
# will run most often, because the question you get asked most often is
# "are we better or worse off than last month?" and the Security Overview
# dashboard does not export.
#
# Requires the gh CLI, authenticated:  gh auth login
#
#   ./scripts/ghas-alert-report.sh you/ghas-pipeline-lab
#   ./scripts/ghas-alert-report.sh --org your-org      # whole organisation

set -euo pipefail

if [[ "${1:-}" == "--org" ]]; then
  SCOPE="orgs/${2:?org name required}"
  LABEL="organisation ${2}"
else
  SCOPE="repos/${1:?repo required as owner/name}"
  LABEL="repository ${1}"
fi

hr() { printf '%*s\n' 72 '' | tr ' ' '-'; }

echo "GHAS alert report — $LABEL — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hr

# --- Code scanning ---------------------------------------------------------
echo "CODE SCANNING (SAST) — open alerts by severity"
gh api --paginate "/$SCOPE/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | .rule.security_severity_level // .rule.severity // "none"' |
  sort | uniq -c | sort -rn || echo "  none / not enabled"

echo
echo "Top rules by open alert count"
gh api --paginate "/$SCOPE/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[].rule.id' | sort | uniq -c | sort -rn | head -10 || true

echo
echo "Oldest open alerts (SLA risk)"
gh api --paginate "/$SCOPE/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | [.created_at, (.rule.security_severity_level // "none"), .rule.id, .html_url] | @tsv' |
  sort | head -10 || true

echo
echo "Dismissed alerts — reason and who (audit trail)"
gh api --paginate "/$SCOPE/code-scanning/alerts?state=dismissed&per_page=100" \
  --jq '.[] | [.dismissed_reason, .dismissed_by.login, .rule.id, (.dismissed_comment // "NO COMMENT")] | @tsv' |
  sort | uniq -c | sort -rn || echo "  none"
hr

# --- Dependabot ------------------------------------------------------------
echo "DEPENDABOT (SCA) — open alerts by severity"
gh api --paginate "/$SCOPE/dependabot/alerts?state=open&per_page=100" \
  --jq '.[].security_advisory.severity' | sort | uniq -c | sort -rn || echo "  none / not enabled"

echo
echo "Open Dependabot alerts with a fix available"
gh api --paginate "/$SCOPE/dependabot/alerts?state=open&per_page=100" \
  --jq '.[] | select(.security_vulnerability.first_patched_version != null)
        | [.security_advisory.severity, .dependency.package.name,
           .security_vulnerability.first_patched_version.identifier, .security_advisory.ghsa_id] | @tsv' |
  sort || true
hr

# --- Secret scanning -------------------------------------------------------
echo "SECRET SCANNING — open alerts"
gh api --paginate "/$SCOPE/secret-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | [.secret_type_display_name, .validity, .html_url] | @tsv' ||
  echo "  none / not enabled"
hr

cat <<'NOTE'
Reading this report:

  * Open count alone is a vanity metric. The numbers that mean something are
    (a) mean age of open critical/high, (b) count past SLA, (c) the ratio of
    dismissed-as-false-positive to fixed — if that ratio climbs, your rules
    are miscalibrated and developers are learning to ignore the tool.
  * "Dismissed with NO COMMENT" is a process failure. Chase every one.
  * Compare against the Veracode baseline you exported before cutover, per
    CWE class, not per finding. Tools count findings differently; CWE classes
    are the only unit that survives a migration.
NOTE
