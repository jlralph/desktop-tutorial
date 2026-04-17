# SAST OWASP Dependency Check

A composite GitHub Action that builds a Spring Boot application, runs an [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) scan to detect known CVEs in project dependencies, and optionally syncs the findings to GitHub Issues.

## What it does

1. **Gets the current date** — stamps a datetime used as the Maven cache key.
2. **Restores Maven cache** — restores `~/.m2/repository` from a datetime-keyed cache to avoid re-downloading the OWASP CVE database on every run.
3. **Builds the Spring Boot app** — runs `mvn -B clean package -DskipTests`.
4. **Runs Dependency Check** — executes `org.owasp:dependency-check-maven:check` and fails if any dependency exceeds the configured CVSS threshold.
5. **Syncs GitHub Issues** — when `github-token` is provided, runs [`scripts/create-cve-issues.sh`](../../../../scripts/create-cve-issues.sh) against the JSON report (always runs, even on scan failure):
   - **Creates** one issue per newly detected CVE
   - **Updates** existing issues when the set of vulnerable packages has changed
   - **Skips** issues where nothing has changed
   - **Closes** issues for CVEs no longer detected in the scan
6. **Uploads artifacts** — uploads the scan report directory to a `dependency-check-results` artifact, retained for 30 days (always runs, even on scan failure).
7. **Saves Maven cache** — persists `~/.m2/repository` under the datetime key for future runs (always runs, even on scan failure).

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `nvd-api-key` | Yes | — | NVD API key for fetching the latest CVE database |
| `pom-file` | No | `pom.xml` | Path to the Maven POM file |
| `max-cvss-score` | No | `8` | Fail the scan if any dependency has a CVSS score above this value |
| `report-dir` | No | `dependency-check-report` | Directory where the scan report is written |
| `format` | No | `JSON` | Report format: `HTML`, `XML`, `CSV`, `JSON`, `JUNIT`, `SARIF`, or `ALL` |
| `github-token` | No | — | Token used to sync CVE findings to GitHub Issues. Requires `issues: write`. If omitted, issue sync is skipped. |

## Issue sync behaviour

When `github-token` is supplied the action calls `scripts/create-cve-issues.sh`, which:

- Fetches all open issues in the repository that carry both the `security` and `vulnerability` labels.
- Compares them against the current scan results, keyed by CVE ID in the issue title.
- Applies the minimal set of changes:

| Condition | Result |
|---|---|
| CVE found in scan, no existing issue | Issue created |
| CVE found in scan, existing issue, same packages | No change |
| CVE found in scan, existing issue, packages differ | Issue body and title updated |
| Existing issue, CVE not found in scan | Issue closed (`not_planned`) |

Each issue is titled `CVE-YYYY-NNNNN [SEVERITY] CVSS X.X` and contains a summary table, description, list of vulnerable Maven packages, and NVD references.

> **Note:** GitHub's REST API does not support issue deletion without `delete_repo` scope. Stale issues are closed with `state_reason: not_planned` instead, preserving audit history.

## Usage

```yaml
on: workflow_dispatch

permissions:
  contents: read
  issues: write        # required for GitHub Issue sync

jobs:
  owasp-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run OWASP Dependency Check
        uses: ./.github/actions/sast-owasp-dependency-check
        with:
          nvd-api-key: ${{ secrets.nvdApiKey }}
          pom-file: 'pom.xml'
          max-cvss-score: '8.5'
          format: 'JSON'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

To run the scan without creating issues, omit `github-token`:

```yaml
      - name: Run OWASP Dependency Check
        uses: ./.github/actions/sast-owasp-dependency-check
        with:
          nvd-api-key: ${{ secrets.nvdApiKey }}
```

See [`sast-owasp-dependency-check.yml`](../../workflows/sast-owasp-dependency-check.yml) for the full example workflow.
