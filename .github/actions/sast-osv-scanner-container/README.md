# SAST OSV Scanner (Container)

A composite GitHub Action that scans a container image for known vulnerabilities using [OSV Scanner](https://github.com/google/osv-scanner) and automatically syncs findings to GitHub Issues.

## What it does

1. **Installs OSV Scanner** — downloads the latest `osv-scanner` binary.
2. **Scans the image** — runs `osv-scanner scan image <image>` and writes results to `osv-results.json`.
3. **Syncs labels** — creates or updates the `security`, `osv-scanner-container`, and `sast` labels on the repository.
4. **Syncs issues** — opens a GitHub Issue for each new vulnerability found and closes issues for vulnerabilities that are no longer detected.
5. **(Optional) Enriches with Dependabot** — when enabled, cross-references findings against the repository's Dependabot alerts to add fix metadata to each issue and respect human triage decisions.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image` | Yes | — | Container image to scan (e.g. `alpine:latest`, `nginx:1.25`) |
| `github-token` | No | `github.token` | Token used to create/update labels and issues. To use `enrich-with-dependabot`, supply a token with Dependabot alerts read access (the default `GITHUB_TOKEN` does not have this scope). |
| `enrich-with-dependabot` | No | `'false'` | When `'true'`, look up matching Dependabot alerts by GHSA/CVE and enrich each issue with the alert link, first patched version, vulnerable range, and any Dependabot auto-fix PR. Issues whose matching Dependabot alert was dismissed are skipped (and any existing issue is closed with a comment quoting the dismissal reason). |

## Labels applied

| Label | Color | Description |
|-------|-------|-------------|
| `security` | `#ee0701` | Security vulnerability |
| `osv-scanner-container` | `#e4e669` | Detected by OSV Container Scanner |
| `sast` | `#6495ED` (cornflower blue) | Static Application Security Testing |

## Usage

```yaml
on: workflow_dispatch

permissions:
  actions: read
  security-events: write
  contents: read
  issues: write

jobs:
  scan-and-create-issues:
    name: Scan & Create Issues
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan container image for vulnerabilities
        uses: ./.github/actions/sast-osv-scanner-container
        with:
          image: alpine:latest
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### With Dependabot enrichment

The default `GITHUB_TOKEN` cannot read Dependabot alerts. Pass a PAT or fine-grained token with **Dependabot alerts: read** access:

```yaml
      - name: Scan container image for vulnerabilities
        uses: ./.github/actions/sast-osv-scanner-container
        with:
          image: alpine:latest
          github-token: ${{ secrets.DEPENDABOT_READ_TOKEN }}
          enrich-with-dependabot: 'true'
```

When enabled, each issue created for a vulnerability that also has a matching Dependabot alert gets an extra **Dependabot** section:

| Field | Value |
|-------|-------|
| **Alert** | Link to the Dependabot alert + current state |
| **First patched** | First version that fixes the vulnerability |
| **Vulnerable range** | Affected version range |
| **Auto-fix PR** | Link to the Dependabot-authored PR, if one exists |

If the matching Dependabot alert has been **dismissed** (e.g. as a false positive or tolerable risk), no new issue is created, and any existing issue is closed with a comment quoting the dismissal reason. This respects human triage decisions made in the Dependabot UI.

See [`sast-osv-scanner-container.yml`](../../workflows/sast-osv-scanner-container.yml) for the full example workflow.
