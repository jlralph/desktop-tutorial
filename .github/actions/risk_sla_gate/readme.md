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

This deterministic SLA enforcement applies only when AI augmentation is **off**.
When `ai-assess` is `true` the SLA check is downgraded to audit-only — a raw SLA
violation never fails the job on its own — and enforcement is delegated to the
AI verdict (see [AI risk assessment](#ai-risk-assessment-optional) below), which
already folds each alert's SLA status into its decision.

## Core inputs

| Input | Default | Purpose |
|---|---|---|
| `github-token` | *(required)* | Token that can read Dependabot alerts (see [Token requirements](#token-requirements)). |
| `repository` | `${{ github.repository }}` | Repository to audit, in `owner/repo` form. |
| `mode` | `audit` | `audit` (report only) or `enforce` (fail on SLA violations). |
| `enforce-severities` | `critical,high` | Severities that fail the job in `enforce` mode. |
| `sla-critical` | `7` | Remediation SLA in days for critical alerts. |
| `sla-high` | `30` | Remediation SLA in days for high alerts. |
| `sla-medium` | `60` | Remediation SLA in days for medium alerts. |
| `sla-low` | `90` | Remediation SLA in days for low alerts. |
| `upload-report` | `true` | Upload the JSON compliance report as a workflow artifact. |
| `report-retention-days` | `90` | Artifact retention (silently clamped to the repo max). |
| `attest-report` | `true` | Generate signed provenance attestations for the report and artifact bundle. |

## Outputs

`result` (`pass` / `fail` / `informational`), `violation-count`,
`enforced-violation-count`, `audited-commit`, `report-path`, `attestation-url`,
and `bundle-attestation-url`. The AI-specific outputs are listed
[below](#additional-outputs-ai).

## AI risk assessment (optional)

Set `ai-assess: "true"` to also have an AI model (via
[GitHub Models](https://docs.github.com/github-models)) weigh the open
Dependabot alerts and emit an overall release-risk verdict. Unlike the
deterministic SLA gate, the model reasons holistically over the findings — and
crucially it receives **each alert's SLA status** (`age_days`, `sla_days`,
`days_over_sla`, `in_violation`), so an item badly past its remediation SLA is
treated as an escalating factor. Findings are also enriched with the
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog, so confirmed in-the-wild exploited CVEs are weighted heavily. The KEV
catalog is cached once per day across runs.

Enabling the AI assessment also **changes what enforces the gate**. The
deterministic SLA check becomes audit-only — its violations are still reported
(and drive the AI's reasoning) but never fail the job on their own. Enforcement
is instead aligned with the AI augmentation: the job fails only on the AI
verdict.

The AI verdict is **advisory by default** — it is always written to the step
summary, the compliance report (under an `ai_assessment` section), and the
`ai-*` / `kev-matched` outputs, but never blocks. To let the verdict fail the
job you need **both** `mode: enforce` **and** `ai-fail-on` set to a severity
**threshold** (e.g. `high` fails on high and critical). In `audit` mode the AI
assessment is report-only — it always runs and records its verdict, but never
blocks. Because the SLA check is audit-only whenever AI augmentation is on,
`ai-fail-on` (not `enforce-severities` or the raw violation count) is the sole
control that can block the job.

The exact prompts sent and the raw model response are logged (collapsed) in the
workflow run for auditability; they contain only public alert metadata and
config inputs — no tokens or secrets.

When `ai-assess` is `false` (the default) no model is called and behavior is
unchanged.

### Additional inputs (AI)

| Input | Default | Purpose |
|---|---|---|
| `ai-assess` | `false` | Enable the AI assessment. |
| `models-token` | `${{ github.token }}` | Token for the GitHub Models API (needs `models: read`). Pass the workflow `GITHUB_TOKEN` — the Dependabot PAT usually lacks this scope. |
| `ai-model` | `openai/gpt-4.1` | Model id in `{publisher}/{model}` form. |
| `deployment-environment` | `production - public internet-facing` | Environment/exposure to calibrate the verdict. |
| `app-context` | *(public web app)* | Free-text description of what is being released. |
| `mitigations` | *(empty)* | Compensating controls (WAF, CDN, network isolation, …). |
| `ai-fail-on` | *(empty)* | Severity threshold at/above which the job fails; empty = advisory only. |
| `max-alerts` | `75` | Max alerts sent to the model (highest-priority first). |

### Additional outputs (AI)

`ai-result`, `ai-risk-level`, `ai-recommendation`, `ai-summary`, `kev-matched`
(all empty when `ai-assess` is disabled).

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
  models: read         # only needed when ai-assess is true

jobs:
  risk-sla-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Risk SLA Gate
        uses: ./.github/actions/risk_sla_gate
        with:
          github-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN }}
          mode: enforce                 # or 'audit'
          enforce-severities: critical,high
          sla-critical: "7"
          sla-high: "30"
          sla-medium: "60"
          sla-low: "90"
          upload-report: "true"
          # Capped at the repo's max artifact retention (default 90); higher values
          # are silently clamped. Raise the repo/org "Artifact and log retention"
          # setting first if your audit policy needs a longer window.
          report-retention-days: "90"
          # --- Optional AI risk assessment (SLA- and KEV-aware) ---
          ai-assess: "true"
          models-token: ${{ github.token }}   # needs 'models: read'
          deployment-environment: "production - public internet-facing"
          ai-fail-on: ""                # empty = advisory; e.g. 'high' to block
```