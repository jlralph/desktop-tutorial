#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Risk AI Advisor
# Gathers open CodeQL code-scanning alerts and open Dependabot alerts, asks an
# AI model (via the GitHub Models inference API) to weigh them together, and
# emits an overall risk verdict for releasing the build to a public-facing
# website. Produces a step summary, a JSON advisory report tied to the audited
# commit, and step outputs. Advisory by default; can fail the job when the
# verdict meets a configurable severity threshold.
# ---------------------------------------------------------------------------

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${MODELS_TOKEN:?MODELS_TOKEN is required}"
: "${REPOSITORY:?REPOSITORY is required}"
DEPENDABOT_TOKEN="${DEPENDABOT_TOKEN:-$GH_TOKEN}"
MODEL="${MODEL:-openai/gpt-4.1}"
APP_CONTEXT="${APP_CONTEXT:-A build being released to a public-facing, internet-exposed website.}"
FAIL_ON="${FAIL_ON:-}"
MAX_ALERTS="${MAX_ALERTS:-75}"
REPORT_PATH="risk-ai-advisor-report-${GITHUB_SHA:-local}.json"

VALID_LEVELS="critical high medium low minimal"

# --- Validate inputs --------------------------------------------------------
if ! [[ "$MAX_ALERTS" =~ ^[0-9]+$ ]]; then
  echo "::error::Input 'max-alerts' must be a non-negative integer (got '${MAX_ALERTS}')."
  exit 1
fi

# Normalize + validate fail-on into a JSON array of levels.
FAIL_ON_JSON=$(jq -nc --arg s "$FAIL_ON" \
  '$s | ascii_downcase | split(",") | map(gsub("\\s+"; "")) | map(select(length > 0)) | unique')
while read -r lvl; do
  [[ -z "$lvl" ]] && continue
  if ! grep -qw "$lvl" <<< "$VALID_LEVELS"; then
    echo "::error::Input 'fail-on' contains invalid risk level '${lvl}'. Valid: ${VALID_LEVELS// /, }."
    exit 1
  fi
done < <(jq -r '.[]' <<< "$FAIL_ON_JSON")

# --- Fetch alerts -----------------------------------------------------------
# Returns a JSON array on stdout. Missing/forbidden (feature disabled or token
# lacks scope) degrades to an empty array with a warning, so the advisor still
# runs on whatever signal it can read.
fetch_alerts() {
  local path="$1" token="$2" name="$3" raw err
  err="$(mktemp)"
  if raw=$(GH_TOKEN="$token" gh api --paginate \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$path" 2>"$err"); then
    jq -s 'add // []' <<< "$raw"
  else
    echo "::warning::Could not read ${name} for ${REPOSITORY}; proceeding without it. Detail: $(tr '\n' ' ' < "$err")" >&2
    echo "[]"
  fi
  rm -f "$err"
}

echo "Collecting open security alerts for ${REPOSITORY} (commit ${GITHUB_SHA:-n/a})..."
CODEQL_RAW=$(fetch_alerts "/repos/${REPOSITORY}/code-scanning/alerts?state=open&per_page=100" "$GH_TOKEN" "CodeQL code-scanning alerts")
DEPENDABOT_RAW=$(fetch_alerts "/repos/${REPOSITORY}/dependabot/alerts?state=open&per_page=100" "$DEPENDABOT_TOKEN" "Dependabot alerts")

# --- Normalize alerts into a compact, model-friendly shape ------------------
# severity rank for ordering (lower = more severe)
SEV_RANK='{"critical":0,"high":1,"error":1,"medium":2,"warning":2,"moderate":2,"low":3,"note":4,"warning_low":4}'

CODEQL=$(jq -c --argjson rank "$SEV_RANK" '
  [ .[] | {
      number: .number,
      rule_id: (.rule.id // .rule.name),
      name: (.rule.name // .rule.id),
      severity: ((.rule.security_severity_level // .rule.severity // "unknown") | ascii_downcase),
      description: (.rule.description // ""),
      file: (.most_recent_instance.location.path // .most_recent_instance.ref // "n/a"),
      tool: (.tool.name // "CodeQL"),
      url: .html_url
    } ]
  | sort_by($rank[.severity] // 5)' <<< "$CODEQL_RAW")

DEPENDABOT=$(jq -c --argjson rank "$SEV_RANK" '
  [ .[] | {
      number: .number,
      severity: ((.security_vulnerability.severity // .security_advisory.severity // "unknown") | ascii_downcase),
      package: (.dependency.package.name // "unknown"),
      ecosystem: (.dependency.package.ecosystem // "unknown"),
      manifest: (.dependency.manifest_path // "n/a"),
      advisory: (.security_advisory.cve_id // .security_advisory.ghsa_id // "N/A"),
      summary: (.security_advisory.summary // ""),
      first_patched_version: (.security_vulnerability.first_patched_version.identifier // "none"),
      url: .html_url
    } ]
  | sort_by($rank[.severity] // 5)' <<< "$DEPENDABOT_RAW")

CODEQL_OPEN=$(jq 'length' <<< "$CODEQL")
DEPENDABOT_OPEN=$(jq 'length' <<< "$DEPENDABOT")
TOTAL_OPEN=$(( CODEQL_OPEN + DEPENDABOT_OPEN ))

# Severity tallies (for the summary table; computed over all alerts, not the truncated set).
count_sev() { jq --arg s "$1" '[ .[] | select(.severity == $s) ] | length' <<< "$2"; }

# Truncate the per-type detail sent to the model to bound prompt size.
CODEQL_SENT=$(jq -c --argjson n "$MAX_ALERTS" '.[0:$n]' <<< "$CODEQL")
DEPENDABOT_SENT=$(jq -c --argjson n "$MAX_ALERTS" '.[0:$n]' <<< "$DEPENDABOT")
CODEQL_TRUNC=$(( CODEQL_OPEN > MAX_ALERTS ? CODEQL_OPEN - MAX_ALERTS : 0 ))
DEPENDABOT_TRUNC=$(( DEPENDABOT_OPEN > MAX_ALERTS ? DEPENDABOT_OPEN - MAX_ALERTS : 0 ))

NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Decide whether we need the model at all --------------------------------
# With zero open alerts there is nothing for the model to weigh; emit a
# deterministic clean verdict and skip the inference call.
if [[ "$TOTAL_OPEN" -eq 0 ]]; then
  echo "No open CodeQL or Dependabot alerts found; recording a clean verdict without calling the model."
  VERDICT=$(jq -nc '{
    risk_level: "minimal",
    recommendation: "go",
    confidence: "high",
    summary: "No open CodeQL or Dependabot alerts were found for this commit.",
    key_risks: [],
    recommended_mitigations: []
  }')
  MODEL_USED="none (no open alerts)"
else
  # --- Build the structured-output request --------------------------------
  SCHEMA=$(jq -nc '{
    type: "object",
    additionalProperties: false,
    properties: {
      risk_level: { type: "string", enum: ["critical","high","medium","low","minimal"] },
      recommendation: { type: "string", enum: ["block","conditional-go","go"] },
      confidence: { type: "string", enum: ["high","medium","low"] },
      summary: { type: "string" },
      key_risks: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            title: { type: "string" },
            severity: { type: "string" },
            source: { type: "string" },
            why_it_matters: { type: "string" }
          },
          required: ["title","severity","source","why_it_matters"]
        }
      },
      recommended_mitigations: { type: "array", items: { type: "string" } }
    },
    required: ["risk_level","recommendation","confidence","summary","key_risks","recommended_mitigations"]
  }')

  SYSTEM_PROMPT="You are a principal application security engineer acting as a release gatekeeper. You assess whether a software build is safe to release to a public-facing, internet-exposed website by reasoning over open static-analysis (CodeQL) findings and open dependency (Dependabot) vulnerabilities. Weigh exploitability from the internet, exposure of the affected code/dependency, severity, and whether fixes are available. Be decisive and concise. Reserve 'critical' for issues that are likely remotely exploitable on a public site with serious impact. Output only what the provided JSON schema allows."

  USER_PROMPT=$(jq -nr \
    --arg ctx "$APP_CONTEXT" \
    --arg repo "$REPOSITORY" \
    --arg sha "${GITHUB_SHA:-n/a}" \
    --argjson codeql "$CODEQL_SENT" \
    --argjson dependabot "$DEPENDABOT_SENT" \
    --argjson codeql_total "$CODEQL_OPEN" \
    --argjson dependabot_total "$DEPENDABOT_OPEN" \
    --argjson codeql_trunc "$CODEQL_TRUNC" \
    --argjson dependabot_trunc "$DEPENDABOT_TRUNC" \
    '"Release context: \($ctx)\n" +
     "Repository: \($repo)\nCommit: \($sha)\n\n" +
     "Open CodeQL alerts: \($codeql_total) (showing \($codeql | length), \($codeql_trunc) omitted for brevity).\n" +
     "Open Dependabot alerts: \($dependabot_total) (showing \($dependabot | length), \($dependabot_trunc) omitted for brevity).\n\n" +
     "CodeQL findings (JSON):\n" + ($codeql | tojson) + "\n\n" +
     "Dependabot findings (JSON):\n" + ($dependabot | tojson) + "\n\n" +
     "Assess the OVERALL risk of releasing this build to the public-facing site described above. Return your verdict per the required schema. In key_risks, list the most release-relevant issues (set source to \"codeql\" or \"dependabot\"). In recommended_mitigations, give concrete, prioritized actions."')

  REQ=$(jq -nc \
    --arg model "$MODEL" \
    --arg sys "$SYSTEM_PROMPT" \
    --arg usr "$USER_PROMPT" \
    --argjson schema "$SCHEMA" '{
      model: $model,
      messages: [
        { role: "system", content: $sys },
        { role: "user", content: $usr }
      ],
      response_format: {
        type: "json_schema",
        json_schema: { name: "release_risk_assessment", strict: true, schema: $schema }
      },
      max_tokens: 1500
    }')

  echo "Requesting risk assessment from GitHub Models (${MODEL})..."
  RESP_FILE=$(mktemp)
  HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
    -X POST "https://models.github.ai/inference/chat/completions" \
    -H "Authorization: Bearer ${MODELS_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2026-03-10" \
    -H "Content-Type: application/json" \
    -d "$REQ" || echo "000")

  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "::error::GitHub Models inference failed (HTTP ${HTTP_CODE}). Ensure the calling job grants 'models: read' and the model id '${MODEL}' is valid. Response: $(tr '\n' ' ' < "$RESP_FILE" | head -c 800)"
    rm -f "$RESP_FILE"
    exit 1
  fi

  CONTENT=$(jq -r '.choices[0].message.content // empty' < "$RESP_FILE")
  rm -f "$RESP_FILE"
  if [[ -z "$CONTENT" ]]; then
    echo "::error::GitHub Models returned no content to parse."
    exit 1
  fi

  if ! VERDICT=$(jq -e . <<< "$CONTENT" 2>/dev/null); then
    echo "::error::Could not parse the model's JSON verdict. Raw content: $(head -c 800 <<< "$CONTENT")"
    exit 1
  fi
  MODEL_USED="$MODEL"
fi

# --- Extract verdict fields --------------------------------------------------
RISK_LEVEL=$(jq -r '.risk_level' <<< "$VERDICT")
RECOMMENDATION=$(jq -r '.recommendation' <<< "$VERDICT")
CONFIDENCE=$(jq -r '.confidence' <<< "$VERDICT")
SUMMARY=$(jq -r '.summary' <<< "$VERDICT")

# --- Determine gate result ---------------------------------------------------
FAIL_ON_COUNT=$(jq 'length' <<< "$FAIL_ON_JSON")
if [[ "$FAIL_ON_COUNT" -eq 0 ]]; then
  RESULT="advisory"
elif jq -e --arg r "$RISK_LEVEL" 'index($r)' <<< "$FAIL_ON_JSON" >/dev/null; then
  RESULT="fail"
else
  RESULT="pass"
fi

# --- Write JSON advisory report (audit evidence) -----------------------------
jq -n \
  --arg commit "${GITHUB_SHA:-}" \
  --arg ref "${GITHUB_REF:-}" \
  --arg repo "$REPOSITORY" \
  --arg workflow "${GITHUB_WORKFLOW:-}" \
  --arg run_id "${GITHUB_RUN_ID:-}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:-}" \
  --arg run_url "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-0}" \
  --arg actor "${GITHUB_ACTOR:-}" \
  --arg assessed_at "$NOW_ISO" \
  --arg model "$MODEL_USED" \
  --arg app_context "$APP_CONTEXT" \
  --arg result "$RESULT" \
  --argjson fail_on "$FAIL_ON_JSON" \
  --argjson codeql_open "$CODEQL_OPEN" \
  --argjson dependabot_open "$DEPENDABOT_OPEN" \
  --argjson codeql_truncated "$CODEQL_TRUNC" \
  --argjson dependabot_truncated "$DEPENDABOT_TRUNC" \
  --argjson verdict "$VERDICT" \
  --argjson codeql "$CODEQL" \
  --argjson dependabot "$DEPENDABOT" \
  '{
    audit: {
      commit_sha: $commit,
      ref: $ref,
      repository: $repo,
      workflow: $workflow,
      run_id: $run_id,
      run_attempt: $run_attempt,
      run_url: $run_url,
      triggered_by: $actor,
      assessed_at: $assessed_at,
      model: $model,
      app_context: $app_context
    },
    policy: {
      result: $result,
      fail_on: $fail_on
    },
    inputs: {
      codeql_open: $codeql_open,
      dependabot_open: $dependabot_open,
      codeql_truncated: $codeql_truncated,
      dependabot_truncated: $dependabot_truncated
    },
    verdict: $verdict,
    alerts: {
      codeql: $codeql,
      dependabot: $dependabot
    }
  }' > "$REPORT_PATH"

echo "Advisory report written to ${REPORT_PATH}"

# --- Step summary ------------------------------------------------------------
risk_emoji() {
  case "$1" in
    critical) echo "🟥" ;; high) echo "🟧" ;; medium) echo "🟨" ;;
    low) echo "🟩" ;; minimal) echo "✅" ;; *) echo "⬜" ;;
  esac
}

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
{
  echo "## 🤖 Risk AI Advisor"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Repository | \`${REPOSITORY}\` |"
  echo "| **Audited commit** | \`${GITHUB_SHA:-n/a}\` |"
  echo "| Assessed at | ${NOW_ISO} |"
  echo "| Model | \`${MODEL_USED}\` |"
  echo "| Open CodeQL alerts | ${CODEQL_OPEN} |"
  echo "| Open Dependabot alerts | ${DEPENDABOT_OPEN} |"
  echo ""
  echo "### $(risk_emoji "$RISK_LEVEL") Verdict: ${RISK_LEVEL^^} — recommendation: \`${RECOMMENDATION}\` (confidence: ${CONFIDENCE})"
  echo ""
  echo "> ${SUMMARY}"
  echo ""
  echo "### Open alerts by severity"
  echo ""
  echo "| Severity | CodeQL | Dependabot |"
  echo "|---|---:|---:|"
  for s in critical high medium low; do
    echo "| ${s} | $(count_sev "$s" "$CODEQL") | $(count_sev "$s" "$DEPENDABOT") |"
  done
  echo ""
  KEY_RISK_COUNT=$(jq '.key_risks | length' <<< "$VERDICT")
  if [[ "$KEY_RISK_COUNT" -gt 0 ]]; then
    echo "### Key risks (${KEY_RISK_COUNT})"
    echo ""
    echo "| Severity | Source | Risk | Why it matters |"
    echo "|---|---|---|---|"
    jq -r '.key_risks[] | "| \(.severity) | \(.source) | \(.title) | \(.why_it_matters) |"' <<< "$VERDICT"
    echo ""
  fi
  MIT_COUNT=$(jq '.recommended_mitigations | length' <<< "$VERDICT")
  if [[ "$MIT_COUNT" -gt 0 ]]; then
    echo "### Recommended mitigations"
    echo ""
    jq -r '.recommended_mitigations[] | "- \(.)"' <<< "$VERDICT"
    echo ""
  fi
  case "$RESULT" in
    advisory) echo "**Result: ℹ️ ADVISORY** — reporting only; no \`fail-on\` threshold is set, so this never blocks." ;;
    pass)     echo "**Result: ✅ PASS** — AI risk level \`${RISK_LEVEL}\` is below the \`fail-on\` threshold ($(jq -r 'join(", ")' <<< "$FAIL_ON_JSON"))." ;;
    fail)     echo "**Result: ❌ FAIL** — AI risk level \`${RISK_LEVEL}\` meets the \`fail-on\` threshold ($(jq -r 'join(", ")' <<< "$FAIL_ON_JSON")). Blocking this release." ;;
  esac
  if [[ "$CODEQL_TRUNC" -gt 0 || "$DEPENDABOT_TRUNC" -gt 0 ]]; then
    echo ""
    echo "_Note: ${CODEQL_TRUNC} CodeQL and ${DEPENDABOT_TRUNC} Dependabot alert(s) were omitted from the model prompt (max-alerts=${MAX_ALERTS}); counts above are complete._"
  fi
} >> "$GITHUB_STEP_SUMMARY"
fi

# --- Outputs -----------------------------------------------------------------
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
{
  echo "result=${RESULT}"
  echo "risk-level=${RISK_LEVEL}"
  echo "recommendation=${RECOMMENDATION}"
  echo "codeql-open=${CODEQL_OPEN}"
  echo "dependabot-open=${DEPENDABOT_OPEN}"
  echo "audited-commit=${GITHUB_SHA:-}"
  echo "report-path=${REPORT_PATH}"
  # summary may contain characters; clamp to one line for the output value.
  echo "summary=$(tr '\n' ' ' <<< "$SUMMARY" | head -c 500)"
} >> "$GITHUB_OUTPUT"
fi

echo "Verdict: ${RISK_LEVEL} | recommendation=${RECOMMENDATION} | result=${RESULT} | codeql=${CODEQL_OPEN} dependabot=${DEPENDABOT_OPEN}"

# --- Enforcement -------------------------------------------------------------
if [[ "$RESULT" == "fail" ]]; then
  echo "::error::Risk AI Advisor: assessed risk level '${RISK_LEVEL}' meets the fail-on threshold. See the job summary and advisory report for details."
  exit 1
fi
