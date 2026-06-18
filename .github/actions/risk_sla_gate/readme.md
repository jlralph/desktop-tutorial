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

## Report signing (audit authenticity)

When `attest-report` is `true` (the default), the action generates signed
[build-provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations)
for two subjects:

1. **The JSON compliance report file** — covers the report content, useful if
   the JSON is extracted from the artifact.
2. **The uploaded artifact bundle (`.zip`)** — covers the exact bundle pulled
   from the run's artifacts during an audit.

Signing is keyless (Sigstore via the workflow's OIDC identity — no private key
to manage), and binds each subject's SHA-256 digest to the producing workflow
run and commit. The attestations are recorded in a public transparency log, so
during a later audit you can prove the report is authentic and was produced by
this pipeline — not edited after the fact:

```bash
# Verify the extracted report file
gh attestation verify risk-sla-gate-report-<sha>.json --repo <owner>/<repo>

# Verify the downloaded artifact bundle
gh attestation verify risk-sla-gate-report-<sha>.zip --repo <owner>/<repo>
```

This requires the calling workflow to grant `id-token: write` and
`attestations: write` permissions (see the example below). The
`attestation-url` and `bundle-attestation-url` outputs record the attestation
locations as audit evidence.

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
  id-token: write      # mint OIDC token for keyless report signing
  attestations: write  # persist the signed provenance attestation

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