# Risk SLA Gate

A composite GitHub Action that audits open Dependabot alerts against
severity-based remediation SLAs. Alert age is measured from the CVE/advisory
published date. Every run is tied to a specific commit SHA, and a JSON
compliance report is uploaded as an artifact named after that SHA so the
review can be evidenced during compliance audits.

## Modes

In `audit` mode the gate reports violations but never fails the job. In
`enforce` mode the job fails when any alert in a severity listed in
`enforce-severities` is over its SLA. Violations in non-enforced severities
are always reported but never block.

## Token requirements

The default `GITHUB_TOKEN` generally cannot read Dependabot alerts. Provide a
fine-grained PAT with the repository permission "Dependabot alerts: read"
(plus "Metadata: read"), or a GitHub App installation token with the same
permission, via a secret.

## Example workflow

```yaml
name: Risk SLA Gate
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read

jobs:
  risk-sla-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Risk SLA Gate
        uses: ./risk_sla_gate
        with:
          github-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN }}
          mode: enforce                 # or 'audit'
          enforce-severities: critical,high
          sla-critical: "7"
          sla-high: "30"
          sla-medium: "60"
          sla-low: "90"
          upload-report: "true"
          report-retention-days: "365"  # align with your audit retention policy
```