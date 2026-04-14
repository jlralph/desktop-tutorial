# SAST OSV Scanner (Container)

A composite GitHub Action that scans a container image for known vulnerabilities using [OSV Scanner](https://github.com/google/osv-scanner) and automatically syncs findings to GitHub Issues.

## What it does

1. **Installs OSV Scanner** — downloads the latest `osv-scanner` binary.
2. **Scans the image** — runs `osv-scanner scan image <image>` and writes results to `osv-results.json`.
3. **Syncs labels** — creates or updates the `security`, `osv-scanner-container`, and `sast` labels on the repository.
4. **Syncs issues** — opens a GitHub Issue for each new vulnerability found and closes issues for vulnerabilities that are no longer detected.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image` | Yes | — | Container image to scan (e.g. `alpine:latest`, `nginx:1.25`) |
| `github-token` | No | `github.token` | Token used to create/update labels and issues |

## Labels applied

| Label | Color | Description |
|-------|-------|-------------|
| `security` | `#ee0701` | Security vulnerability |
| `osv-scanner-container` | `#e4e669` | Detected by OSV Container Scanner |
| `sast` | `#6495ED` (cornflower blue) | Static Application Security Testing |

## Usage

```yaml
jobs:
  scan-and-create-issues:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan container image for vulnerabilities
        uses: ./.github/actions/sast-osv-scanner-container
        with:
          image: alpine:latest
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

See [`sast-osv-scanner-container.yml`](../../workflows/sast-osv-scanner-container.yml) for the full example workflow.

## Permissions required

The calling workflow must grant:

```yaml
permissions:
  issues: write
  contents: read
```
