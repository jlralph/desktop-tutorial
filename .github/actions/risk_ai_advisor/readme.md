# Risk AI Advisor

A composite GitHub Action that uses an AI model to judge whether a build is safe
to release to a **public-facing website**. It reads the repository's open
**CodeQL code-scanning** alerts and open **Dependabot** alerts, enriches the
Dependabot findings with the [CISA Known Exploited Vulnerabilities (KEV)
catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), sends
them to a model via the [GitHub Models](https://docs.github.com/en/github-models)
inference API, and returns a single overall risk verdict — risk level,
go/no-go recommendation, key risks, and recommended mitigations.

Every run is tied to a commit SHA and a JSON advisory report is uploaded as an
artifact named after that SHA, so the assessment can be evidenced later.

## What it does

1. Fetches open CodeQL alerts (`GET /repos/{owner}/{repo}/code-scanning/alerts`).
2. Fetches open Dependabot alerts (`GET /repos/{owner}/{repo}/dependabot/alerts`).
3. Downloads the CISA KEV catalog and flags any Dependabot alert whose CVE is
   listed as actively exploited in the wild (`known_exploited`), attaching the
   KEV record (date added, due date, ransomware use, required action). Matched
   alerts sort first so they survive `max-alerts` truncation, and the model is
   told to weigh them decisively toward blocking.
4. Normalizes and severity-sorts them, then asks the model to weigh them
   together in the context of an internet-exposed deployment.
5. Receives a **structured** verdict (enforced via the inference API's
   `json_schema` response format):

   ```json
   {
     "risk_level": "high",
     "recommendation": "conditional-go",
     "confidence": "medium",
     "summary": "One SQL-injection finding on a public endpoint dominates the risk...",
     "key_risks": [
       { "title": "SQL injection in /search", "severity": "high", "source": "codeql", "why_it_matters": "Reachable unauthenticated from the internet." }
     ],
     "recommended_mitigations": ["Parameterize the /search query before release", "..."]
   }
   ```

6. Writes a job summary, a JSON report artifact, and step outputs. The summary
   includes a dedicated table of KEV-listed (known-exploited) CVEs when any are
   matched.

If there are **no** open alerts, the action records a deterministic
`minimal` / `go` verdict and skips the model call.

## CISA KEV enrichment

Before calling the model, the action fetches the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and matches each open Dependabot alert's CVE against it. Matches are annotated
with `known_exploited: true` and a `kev` record, surfaced in a dedicated summary
table, and reported via the `kev-matched` output. A KEV match means confirmed
in-the-wild exploitation, so the model is instructed to treat it as a strong
escalating factor toward blocking a public-facing release.

The catalog is cached across runs via `actions/cache`, keyed per UTC day, so only
the first run each day downloads it. A network or parse failure degrades to an
empty catalog and a warning — the advisor still runs on the rest of the signal.

## Advisory vs. blocking

By default the action is **advisory** — it always reports a verdict but never
fails the job. Set `fail-on` to a comma-separated list of risk levels
(`critical`, `high`, `medium`, `low`, `minimal`) to turn it into a release gate:
the job fails when the AI risk level is one of those listed.

```yaml
fail-on: "critical,high"   # block the release on a high-or-worse verdict
```

> The AI verdict is a decision aid, not a guarantee. Treat a blocking
> configuration as defense-in-depth alongside your other gates, and keep a human
> in the loop for release decisions.

## Tokens & permissions

| Need | How |
|---|---|
| Read CodeQL alerts | `security-events: read` on the calling job's `GITHUB_TOKEN` (the action's `github-token` input). |
| Call GitHub Models | `models: read` on the same `GITHUB_TOKEN`. |
| Read Dependabot alerts | The default `GITHUB_TOKEN` generally **cannot** read Dependabot alerts. Provide a fine-grained PAT (repository permission "Dependabot alerts: read" + "Metadata: read") or a GitHub App installation token via `dependabot-token`. |

If a source can't be read (feature disabled or token lacks scope), the action
logs a warning and proceeds on whatever signal it can read rather than failing.

## Inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | `${{ github.token }}` | Reads CodeQL alerts and calls GitHub Models. Needs `security-events: read` + `models: read`. |
| `dependabot-token` | `${{ github.token }}` | Reads Dependabot alerts. Use a PAT/App token with "Dependabot alerts: read". |
| `repository` | `${{ github.repository }}` | Repo to assess, `owner/repo`. |
| `model` | `openai/gpt-4.1` | GitHub Models model, `{publisher}/{model}`. |
| `app-context` | _(generic public-site text)_ | Description of what's being released and its exposure — sharper context, sharper verdict. |
| `fail-on` | `""` | Comma-separated risk levels that fail the job. Empty = advisory only. |
| `max-alerts` | `75` | Max alerts of each type sent to the model (counts are always reported in full). |
| `upload-report` | `true` | Upload the JSON report as an artifact. |
| `report-retention-days` | `90` | Artifact retention period. |

## Outputs

| Output | Description |
|---|---|
| `result` | `advisory`, `pass`, or `fail`. |
| `risk-level` | `critical` / `high` / `medium` / `low` / `minimal`. |
| `recommendation` | `block` / `conditional-go` / `go`. |
| `summary` | One-line AI summary. |
| `codeql-open` | Open CodeQL alerts considered. |
| `dependabot-open` | Open Dependabot alerts considered. |
| `kev-matched` | Open Dependabot alerts whose CVE is in the CISA KEV catalog. |
| `audited-commit` | Commit SHA assessed. |
| `report-path` | Path to the JSON report. |

## Example workflow

```yaml
name: Risk AI Advisor
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: read   # read CodeQL code-scanning alerts
  models: read            # call the GitHub Models inference API

jobs:
  risk-ai-advisor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Assess release risk with AI
        id: advisor
        uses: ./.github/actions/risk_ai_advisor
        with:
          # GITHUB_TOKEN cannot read Dependabot alerts — supply a scoped token.
          dependabot-token: ${{ secrets.DEPENDABOT_ALERTS_TOKEN }}
          model: openai/gpt-4.1
          app-context: >-
            Public-facing Java web application handling user authentication and
            payments, deployed to the public internet behind a CDN.
          fail-on: "critical"      # or "" for advisory-only
          max-alerts: "75"

      - name: Echo verdict
        if: always()
        run: |
          echo "Result:         ${{ steps.advisor.outputs.result }}"
          echo "Risk level:     ${{ steps.advisor.outputs.risk-level }}"
          echo "Recommendation: ${{ steps.advisor.outputs.recommendation }}"
          echo "KEV matched:    ${{ steps.advisor.outputs.kev-matched }}"
          echo "Summary:        ${{ steps.advisor.outputs.summary }}"
```
