# Risk SLA Gate

A composite GitHub Action that audits open Dependabot alerts against
severity-based remediation SLAs. Alert age is measured from the CVE/advisory
published date. Every run is tied to a specific commit SHA, and a JSON
compliance report is uploaded as an artifact named after that SHA so the
review can be evidenced during compliance audits.

## Modes

In `audit` mode the gate reports violations but never fails the job. In
`enforce` mode the job fails when any **in-scope** alert is over its SLA.

## Severity threshold

A single `severity-threshold` (`critical` / `high` / `medium` / `low`, or empty
for all severities) governs **both** gates and filters the alert set:

- Only alerts at the threshold **or higher** are evaluated — anything below is
  filtered out entirely, from the counts, the JSON compliance report, the step
  summary, and the AI prompt (the number filtered out is always reported so the
  exclusion is never silent).
- The deterministic SLA gate enforces on those in-scope severities.
- The AI verdict's fail-on level is set to this same threshold.

So one knob decides what "counts" and what can fail the job. With the threshold
empty (default) nothing is filtered, and in `enforce` mode with AI off any SLA
violation can fail the job.

This deterministic SLA enforcement applies only when AI augmentation is **off**.
When `ai-assess` is `true` the SLA check is downgraded to audit-only — a raw SLA
violation never fails the job on its own — and enforcement is delegated to the
AI verdict (see [AI risk assessment](#ai-risk-assessment-optional) below), whose
fail-on level is the chosen `severity-threshold`.

## Core inputs

| Input | Default | Purpose |
|---|---|---|
| `github-token` | *(required)* | Token that can read Dependabot alerts (see [Token requirements](#token-requirements)). |
| `repository` | `${{ github.repository }}` | Repository to audit, in `owner/repo` form. |
| `mode` | `audit` | `audit` (report only) or `enforce` (fail on SLA violations). |
| `severity-threshold` | *(empty)* | Min severity governing both gates and the filter (`critical`/`high`/`medium`/`low`; empty = all). See [Severity threshold](#severity-threshold). |
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
job you need **both** `mode: enforce` **and** a `severity-threshold` set (e.g.
`high` fails when the AI risk verdict is high or critical). In `audit` mode the
AI assessment is report-only — it always runs and records its verdict, but never
blocks. Because the SLA check is audit-only whenever AI augmentation is on, the
`severity-threshold` (not the raw violation count) is the sole control that can
block the job. Note that the model only ever sees in-scope alerts — anything
below the threshold is filtered out before the prompt is built.

The exact prompts sent and the raw model response are logged (collapsed) in the
workflow run for auditability. They contain public alert metadata plus the
free-text config inputs (`app-context`, `mitigations`, `deployment-environment`)
verbatim — the action never puts tokens or secrets in them, so make sure the
caller doesn't either (see [Security notes](#security-notes)).

When `ai-assess` is `false` (the default) no model is called and behavior is
unchanged.

### Additional inputs (AI)

| Input | Default | Purpose |
|---|---|---|
| `ai-assess` | `false` | Enable the AI assessment. |
| `ai-endpoint` | GitHub Models URL | Full URL of an OpenAI-compatible chat/completions endpoint. See [Choosing an AI provider](#choosing-an-ai-provider). |
| `ai-auth-scheme` | `bearer` | `bearer` (`Authorization: Bearer …`) for OpenAI/OpenRouter/Groq/Azure-with-Entra/GitHub Models, or `api-key` for Azure OpenAI resource keys. |
| `models-token` | `${{ github.token }}` | Token/key sent to the endpoint. For GitHub Models, pass the workflow `GITHUB_TOKEN` (needs `models: read`); for other providers, pass their API key via a secret. |
| `ai-model` | `openai/gpt-4.1` | Model id. Shape depends on the endpoint (GitHub Models: `{publisher}/{model}`; OpenAI: bare id; Azure: deployment name — often in the URL). |
| `deployment-environment` | `production - public internet-facing` | Environment/exposure to calibrate the verdict. |
| `app-context` | *(public web app)* | Free-text description of what is being released. |
| `mitigations` | *(empty)* | Compensating controls (WAF, CDN, network isolation, …). |
| `max-alerts` | `75` | Max alerts sent to the model (highest-priority first). |

### Choosing an AI provider

GitHub Models was **fully retired on 2026-07-30**. The default `ai-endpoint`
still points at the (now-410-returning) GitHub Models URL so existing callers
who leave `ai-assess: false` are unaffected; anyone turning AI on must point
`ai-endpoint` at a live OpenAI-compatible provider. Any provider that speaks
the OpenAI chat/completions request shape will work. Common choices:

| Provider | `ai-endpoint` | `ai-auth-scheme` | `ai-model` example |
|---|---|---|---|
| OpenAI | `https://api.openai.com/v1/chat/completions` | `bearer` | `gpt-4.1` |
| OpenRouter | `https://openrouter.ai/api/v1/chat/completions` | `bearer` | `openai/gpt-4.1` |
| Groq | `https://api.groq.com/openai/v1/chat/completions` | `bearer` | `llama-3.3-70b-versatile` |
| Azure OpenAI (resource key) | `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-10-21` | `api-key` | *(deployment name; usually ignored)* |
| Azure OpenAI (Entra token) | *(same URL as above)* | `bearer` | *(same as above)* |

Pass the provider's API key as `models-token` via a repo/org secret.

The blocking threshold is the shared [`severity-threshold`](#severity-threshold)
input, not an AI-specific one.

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

## Security notes

- **Alert metadata is untrusted input to the AI.** `package`, `ecosystem`,
  `manifest_path`, `cve_id`, advisory titles, and the alert URL all originate
  from third-party dependency metadata and are passed to the model as data. The
  system prompt tells the model to disregard directive-looking text in those
  fields, and output is constrained by a strict JSON schema — but a hostile
  advisory could still bias a verdict. Because the AI is advisory unless
  `mode: enforce` **and** `severity-threshold` are both set, keep that in mind
  when relying on the AI verdict to block releases.
- **Free-text inputs are logged and persisted.** `app-context`, `mitigations`,
  and `deployment-environment` are echoed to the workflow log (collapsed
  `::group::` blocks) and merged into the signed compliance report. Do not
  pass secrets in these fields.
- **Third-party actions are pinned by SHA.** `actions/attest-build-provenance`
  and `actions/upload-artifact` are pinned to commit SHAs (with the tag noted
  in a trailing comment). If you fork this action, keep them pinned — a
  compromised floating tag would run with `id-token: write` and
  `attestations: write`.
- **Report authenticity.** Every report is signed with a Sigstore
  build-provenance attestation, so a downstream consumer can verify the file
  came from this workflow run with `gh attestation verify` — a tampered report
  will fail verification.

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
          # One knob for both gates + the filter: only high/critical are
          # evaluated, enforced, and sent to the AI. Empty = all severities.
          severity-threshold: high
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
          # With ai-assess on, the SLA check is audit-only and the AI verdict
          # (fail-on = severity-threshold above) is what blocks in enforce mode.
          # GitHub Models retired 2026-07-30 — repoint at a live OpenAI-compatible
          # endpoint (see "Choosing an AI provider").
          ai-assess: "true"
          ai-endpoint: https://api.openai.com/v1/chat/completions
          ai-auth-scheme: bearer
          models-token: ${{ secrets.OPENAI_API_KEY }}
          ai-model: gpt-4.1
          deployment-environment: "production - public internet-facing"
```