#!/usr/bin/env bash
#
# Run CodeQL locally, exactly the way a Jenkins stage or an Azure DevOps task
# would. This is the portable path: if your company's CI is not GitHub Actions,
# this script IS your integration. It produces SARIF, and SARIF is what the
# Security tab consumes.
#
#   ./scripts/run-codeql-local.sh                    # analyse, write SARIF
#   GH_TOKEN=xxx REPO=you/repo ./scripts/run-codeql-local.sh --upload
#
# Why run it locally at all: a CodeQL alert takes minutes to appear in a PR.
# When you are tuning a custom query or arguing about a false positive, the
# local loop is seconds, and you can inspect the database directly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="${CODEQL_DB:-$ROOT/.codeql-db}"
SARIF="${SARIF_OUT:-$ROOT/codeql-results.sarif}"
LANG="${CODEQL_LANG:-python}"

command -v codeql >/dev/null || {
  echo "codeql CLI not found on PATH." >&2
  echo "Download the bundle (CLI + precompiled queries) from:" >&2
  echo "  https://github.com/github/codeql-action/releases/latest" >&2
  echo "  file: codeql-bundle-linux64.tar.gz  — extract and add codeql/ to PATH" >&2
  echo "Use the BUNDLE, not the bare CLI: the bundle ships the query packs and" >&2
  echo "the versions GitHub itself runs, so local results match CI results." >&2
  exit 1
}

echo "==> Building CodeQL database ($LANG)"
codeql database create "$DB" \
  --language="$LANG" \
  --source-root="$ROOT" \
  --overwrite

echo "==> Analysing (security-extended + company policy queries)"
codeql database analyze "$DB" \
  "codeql/${LANG}-queries:codeql-suites/${LANG}-security-extended.qls" \
  "$ROOT/.github/codeql/custom-queries" \
  --format=sarif-latest \
  --output="$SARIF" \
  --sarif-category="/language:${LANG}" \
  --download

echo "==> Results written to $SARIF"
python3 - "$SARIF" <<'PY'
import collections, json, sys
with open(sys.argv[1]) as fh:
    sarif = json.load(fh)
counts = collections.Counter()
for run in sarif["runs"]:
    rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
    for res in run.get("results", []):
        rule = rules.get(res.get("ruleId"), {})
        sev = (rule.get("properties", {}) or {}).get("security-severity")
        band = "none"
        if sev:
            s = float(sev)
            band = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        counts[band] += 1
        print(f"  {band:8} {res.get('ruleId'):50} {res['locations'][0]['physicalLocation']['artifactLocation']['uri']}")
print("\nTotals:", dict(counts))
PY

if [[ "${1:-}" == "--upload" ]]; then
  : "${GH_TOKEN:?set GH_TOKEN}"
  : "${REPO:?set REPO as owner/name}"
  echo "==> Uploading SARIF to $REPO"
  codeql github upload-results \
    --repository="$REPO" \
    --ref="refs/heads/$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)" \
    --commit="$(git -C "$ROOT" rev-parse HEAD)" \
    --sarif="$SARIF" \
    --github-auth-stdin <<<"$GH_TOKEN"
  echo "==> Uploaded. Check the Security tab."
fi
