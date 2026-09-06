# Running GHAS when your CI is not GitHub Actions

The mental model, which is worth more than any of the snippets below:

> **GitHub is the findings platform. Your CI is just somewhere to run scanners.
> SARIF is the contract between them.**

Anything that produces SARIF can populate the Security tab, get triaged in the
same queue, respect the same dismissals, and be queried through the same API.
Actions is the most convenient producer, not the only one.

## What you need in any CI system

1. The **CodeQL bundle** on the agent (CLI + query packs, one tarball).
   Cache it — it is ~900 MB and you do not want to download it per build.
2. A **token** with `security_events: write` on the target repository. Use a
   GitHub App installation token, not a PAT: PATs are tied to a leaver.
3. Three commands: `database create`, `database analyze`, `github upload-results`.

That is the entire integration. `scripts/run-codeql-local.sh` is a working
implementation of all three.

## Jenkins

```groovy
pipeline {
  agent { label 'linux' }
  environment {
    CODEQL_HOME = '/opt/codeql'                 // pre-baked into the agent image
    PATH        = "/opt/codeql:${env.PATH}"
  }
  stages {
    stage('CodeQL') {
      steps {
        sh '''
          codeql database create codeql-db --language=python --source-root=. --overwrite
          codeql database analyze codeql-db \
            codeql/python-queries:codeql-suites/python-security-extended.qls \
            .github/codeql/custom-queries \
            --format=sarif-latest --output=codeql.sarif \
            --sarif-category=/language:python
        '''
        withCredentials([string(credentialsId: 'ghas-app-token', variable: 'GH_TOKEN')]) {
          sh '''
            echo "$GH_TOKEN" | codeql github upload-results \
              --repository="$GIT_ORG/$GIT_REPO" \
              --ref="refs/heads/$BRANCH_NAME" \
              --commit="$GIT_COMMIT" \
              --sarif=codeql.sarif \
              --github-auth-stdin
          '''
        }
      }
    }
    stage('Policy gate') {
      steps {
        withCredentials([string(credentialsId: 'ghas-app-token', variable: 'GH_TOKEN')]) {
          sh 'GITHUB_REPOSITORY="$GIT_ORG/$GIT_REPO" python3 scripts/policy_gate.py'
        }
      }
    }
  }
}
```

Two Jenkins-specific traps:

- **`--ref` must be a real ref GitHub knows**, `refs/heads/<branch>` or
  `refs/pull/<n>/merge`. Jenkins' `BRANCH_NAME` is often the short name; if the
  upload silently produces no alerts, this is why, nine times out of ten.
- **`--commit` must be the SHA that is actually on GitHub.** If Jenkins builds
  a merge commit it created locally, GitHub cannot match it and the results are
  discarded without an error you will notice.

## Azure DevOps

The same three commands in a `script:` step. There is also a first-party
"GitHub Advanced Security for Azure DevOps" product — note that this is a
*different SKU* that puts results in the ADO Advanced Security tab, not in
GitHub. If your code lives on GitHub and only your pipelines are in ADO, you
want the CLI + SARIF upload path above, not that product. Getting this wrong is
an expensive purchase order.

## Third-party scanners

Same pattern, different producer — see `.github/workflows/third-party-sarif.yml`.
Two rules that will save you a bad week:

- **Give every tool its own `category`.** Uploads replace previous results *in
  the same category*. Two tools sharing a category means each run silently
  deletes the other's findings.
- **Upload SARIF even when the tool exits non-zero.** Collect results and
  enforce policy in separate steps, or a failing scan means no findings at all
  — the worst of both outcomes.

## SARIF gotchas worth knowing before you hit them

| Symptom | Cause |
| --- | --- |
| Upload succeeds, no alerts appear | `--ref` / `--commit` don't match a real GitHub ref |
| Alerts vanish after another tool runs | Two tools sharing a `category` |
| Every alert re-opens each run | Unstable `partialFingerprints` — the tool isn't emitting them; findings get new identities each scan |
| "SARIF too large" | 10 MB / 25,000 results per upload. Split by category or narrow the suite |
| Severities look wrong in rulesets | Rulesets read `security-severity` (CVSS), not SARIF `level`. A tool emitting only `level` gets treated as unset |

The fingerprint one is the subtle killer: without stable fingerprints, a
dismissal does not stick, because next run's "same" alert is a different alert.
If a tool's alerts keep resurrecting, check `partialFingerprints` in its SARIF
before you blame GitHub.
