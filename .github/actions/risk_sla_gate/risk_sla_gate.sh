#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Risk SLA Gate
# Queries open Dependabot alerts, computes age from the CVE published date,
# and compares against severity-based SLAs. Produces a step summary and a
# JSON compliance report tied to the audited commit SHA.
# ---------------------------------------------------------------------------

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPOSITORY:?REPOSITORY is required}"
MODE="${MODE:-audit}"
ENFORCE_SEVERITIES="${ENFORCE_SEVERITIES:-critical,high}"
REPORT_PATH="risk-sla-gate-report-${GITHUB_SHA}.json"

# --- Optional AI risk assessment ---------------------------------------------
# When AI_ASSESS=true, after the deterministic SLA evaluation the gate also asks a
# GitHub Models LLM to weigh the open alerts — with their SLA status included — and
# emit an overall risk verdict. Advisory by default; AI_FAIL_ON can make it block.
AI_ASSESS="${AI_ASSESS:-false}"
# Token used for the GitHub Models inference API (needs 'models: read'). The
# Dependabot PAT in GH_TOKEN usually lacks that scope, so this defaults to it only
# as a fallback — callers should pass the workflow's GITHUB_TOKEN via models-token.
MODELS_TOKEN="${MODELS_TOKEN:-$GH_TOKEN}"
AI_MODEL="${AI_MODEL:-openai/gpt-4.1}"
DEPLOYMENT_ENVIRONMENT="${DEPLOYMENT_ENVIRONMENT:-production - public internet-facing}"
APP_CONTEXT="${APP_CONTEXT:-A build being released to a public-facing, internet-exposed website.}"
# Compensating controls (WAF, load balancer, etc.) selected for this run, if any.
MITIGATIONS="${MITIGATIONS:-}"
AI_FAIL_ON="${AI_FAIL_ON:-}"
MAX_ALERTS="${MAX_ALERTS:-75}"
AI_VALID_LEVELS="critical high medium low minimal"

# --- Validate inputs --------------------------------------------------------
if [[ "$MODE" != "enforce" && "$MODE" != "audit" ]]; then
  echo "::error::Input 'mode' must be 'enforce' or 'audit' (got '${MODE}')."
  exit 1
fi

for var in SLA_CRITICAL SLA_HIGH SLA_MEDIUM SLA_LOW; do
  if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
    echo "::error::Input '${var}' must be a non-negative integer (got '${!var}')."
    exit 1
  fi
done

# Normalize + validate the AI fail-on threshold list (only meaningful when AI is
# enabled, but validated unconditionally so a typo surfaces early).
AI_FAIL_ON_JSON=$(jq -nc --arg s "$AI_FAIL_ON" \
  '$s | ascii_downcase | split(",") | map(gsub("\\s+"; "")) | map(select(length > 0)) | unique')
while read -r lvl; do
  [[ -z "$lvl" ]] && continue
  if ! grep -qw "$lvl" <<< "$AI_VALID_LEVELS"; then
    echo "::error::Input 'ai-fail-on' contains invalid risk level '${lvl}'. Valid: ${AI_VALID_LEVELS// /, }."
    exit 1
  fi
done < <(jq -r '.[]' <<< "$AI_FAIL_ON_JSON")

if [[ "$AI_ASSESS" == "true" ]]; then
  if ! [[ "$MAX_ALERTS" =~ ^[0-9]+$ ]]; then
    echo "::error::Input 'max-alerts' must be a non-negative integer (got '${MAX_ALERTS}')."
    exit 1
  fi
  : "${MODELS_TOKEN:?MODELS_TOKEN is required when ai-assess is true}"
fi

SLAS=$(jq -nc \
  --argjson c "$SLA_CRITICAL" --argjson h "$SLA_HIGH" \
  --argjson m "$SLA_MEDIUM" --argjson l "$SLA_LOW" \
  '{critical: $c, high: $h, medium: $m, low: $l}')

ENFORCE_JSON=$(jq -nc --arg s "$ENFORCE_SEVERITIES" \
  '$s | ascii_downcase | split(",") | map(gsub("\\s+"; "")) | map(select(length > 0))')

# --- Query open Dependabot alerts -------------------------------------------
echo "Querying open Dependabot alerts for ${REPOSITORY} (commit ${GITHUB_SHA})..."
if ! RAW=$(gh api --paginate \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "/repos/${REPOSITORY}/dependabot/alerts?state=open&per_page=100"); then
  echo "::error::Failed to query Dependabot alerts. Verify the token has 'Dependabot alerts: read' permission and that Dependabot alerts are enabled for ${REPOSITORY}."
  exit 1
fi
ALERTS=$(jq -s 'add // []' <<< "$RAW")

# --- Evaluate alerts against SLA policy --------------------------------------
NOW_EPOCH=$(date -u +%s)
NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

EVALUATED=$(jq -c \
  --argjson now "$NOW_EPOCH" \
  --argjson slas "$SLAS" \
  --arg ws "${GITHUB_WORKSPACE:-}" '
  def rank: {"critical": 0, "high": 1, "medium": 2, "low": 3};
  # Normalize a manifest path to a repo-relative form so the same file reported
  # with different prefixes (an absolute runner-workspace path vs a plain
  # "pom.xml") collapses to one value. Without this, one vulnerability in one
  # file can appear as two rows when Dependabot surfaces it as separate alerts.
  def norm_manifest:
    ( (. // "")
      | ltrimstr("/")
      | (if ($ws | length) > 0 then ltrimstr(($ws | ltrimstr("/")) + "/") else . end)
      | sub("^home/runner/work/[^/]+/[^/]+/"; "")
      | ltrimstr("./") );
  [ .[]
    | ((.security_vulnerability.severity // .security_advisory.severity // "low") | ascii_downcase) as $sev
    | ((.security_advisory.published_at // .created_at)) as $pub_iso
    | ($pub_iso | fromdateiso8601) as $pub
    | ((($now - $pub) / 86400) | floor) as $age
    | ($slas[$sev] // $slas["low"]) as $sla
    | {
        alert_number: .number,
        package: .dependency.package.name,
        ecosystem: .dependency.package.ecosystem,
        manifest_path: (.dependency.manifest_path | norm_manifest),
        cve_id: (.security_advisory.cve_id // .security_advisory.ghsa_id // "N/A"),
        cve: (.security_advisory.cve_id // ""),
        ghsa_id: .security_advisory.ghsa_id,
        severity: $sev,
        cve_published_at: $pub_iso,
        age_days: $age,
        sla_days: $sla,
        days_over_sla: (if $age > $sla then ($age - $sla) else 0 end),
        in_violation: ($age > $sla),
        first_patched_version: (.security_vulnerability.first_patched_version.identifier // "none"),
        alert_url: .html_url
      }
  ]
  # Collapse duplicates: the same package + vulnerability in the same (normalized)
  # manifest is one finding even if it surfaces as multiple Dependabot alerts.
  # Keep the lowest alert number for a stable, deterministic choice. This dedupe
  # flows into the counts, the JSON report, and the summary so they all agree.
  | group_by([.package, .ecosystem, .cve_id, .manifest_path])
  | map(min_by(.alert_number))
  | sort_by([(rank[.severity] // 4), -(.days_over_sla)])' <<< "$ALERTS")

VIOLATIONS=$(jq -c '[ .[] | select(.in_violation) ]' <<< "$EVALUATED")
TOTAL_OPEN=$(jq 'length' <<< "$EVALUATED")
VIOLATION_COUNT=$(jq 'length' <<< "$VIOLATIONS")
ENFORCED_COUNT=$(jq --argjson e "$ENFORCE_JSON" \
  '[ .[] | select(.severity as $s | $e | index($s)) ] | length' <<< "$VIOLATIONS")

# The deterministic SLA gate only ever fails the job on its own when AI
# augmentation is OFF. When AI_ASSESS=true the SLA portion is downgraded to
# audit (report-only) and enforcement is delegated to the AI verdict, so the
# SLA result is informational regardless of mode.
if [[ "$MODE" == "audit" || "$AI_ASSESS" == "true" ]]; then
  RESULT="informational"
elif [[ "$ENFORCED_COUNT" -gt 0 ]]; then
  RESULT="fail"
else
  RESULT="pass"
fi

# --- Write JSON compliance report (audit evidence) ---------------------------
jq -n \
  --arg commit "$GITHUB_SHA" \
  --arg ref "${GITHUB_REF:-}" \
  --arg repo "$REPOSITORY" \
  --arg workflow "${GITHUB_WORKFLOW:-}" \
  --arg run_id "${GITHUB_RUN_ID:-}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:-}" \
  --arg run_url "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-0}" \
  --arg actor "${GITHUB_ACTOR:-}" \
  --arg evaluated_at "$NOW_ISO" \
  --arg mode "$MODE" \
  --arg result "$RESULT" \
  --argjson slas "$SLAS" \
  --argjson enforce "$ENFORCE_JSON" \
  --argjson total "$TOTAL_OPEN" \
  --argjson violations_count "$VIOLATION_COUNT" \
  --argjson enforced_count "$ENFORCED_COUNT" \
  --argjson alerts "$EVALUATED" \
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
      evaluated_at: $evaluated_at
    },
    policy: {
      mode: $mode,
      sla_days: $slas,
      enforced_severities: $enforce
    },
    summary: {
      result: $result,
      open_alerts: $total,
      sla_violations: $violations_count,
      enforced_violations: $enforced_count
    },
    alerts: $alerts
  }' > "$REPORT_PATH"

echo "Compliance report written to ${REPORT_PATH}"

# --- Write step summary -------------------------------------------------------
{
  echo "## 🛡️ Risk SLA Gate"
  echo ""
  echo "| Audit Field | Value |"
  echo "|---|---|"
  echo "| Repository | \`${REPOSITORY}\` |"
  echo "| **Audited commit** | \`${GITHUB_SHA}\` |"
  echo "| Ref | \`${GITHUB_REF:-n/a}\` |"
  echo "| Workflow run | [${GITHUB_RUN_ID:-n/a} (attempt ${GITHUB_RUN_ATTEMPT:-1})](${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-0}) |"
  echo "| Evaluated at | ${NOW_ISO} |"
  echo "| Mode | \`${MODE}\` |"
  echo "| Enforced severities | \`$(jq -r 'join(", ")' <<< "$ENFORCE_JSON")\` |"
  echo ""
  echo "### SLA Policy (days from CVE published date)"
  echo ""
  echo "| Severity | SLA (days) | Open Alerts | Over SLA |"
  echo "|---|---:|---:|---:|"
  jq -r --argjson slas "$SLAS" '
    . as $a
    | ("critical", "high", "medium", "low")
    | . as $s
    | "| \($s) | \($slas[$s]) | \([$a[] | select(.severity == $s)] | length) | \([$a[] | select(.severity == $s and .in_violation)] | length) |"
  ' <<< "$EVALUATED"
  echo ""
  if [[ "$VIOLATION_COUNT" -gt 0 ]]; then
    echo "### ❌ Dependencies over SLA (${VIOLATION_COUNT})"
    echo ""
    echo "| Severity | Package | Manifest | CVE | Published | Age (d) | SLA (d) | Over by (d) | Fixed in | Alert |"
    echo "|---|---|---|---|---|---:|---:|---:|---|---|"
    jq -r '.[] | "| \(.severity) | \(.package) (\(.ecosystem)) | \(.manifest_path) | \(.cve_id) | \(.cve_published_at[0:10]) | \(.age_days) | \(.sla_days) | **\(.days_over_sla)** | \(.first_patched_version) | [#\(.alert_number)](\(.alert_url)) |"' <<< "$VIOLATIONS"
  else
    echo "### ✅ No dependencies over SLA"
  fi
  echo ""
  case "$RESULT" in
    pass)          echo "**Result: ✅ PASS** — no SLA violations in enforced severities." ;;
    fail)          echo "**Result: ❌ FAIL** — ${ENFORCED_COUNT} violation(s) in enforced severities. The gate is blocking this commit." ;;
    informational) if [[ "$MODE" != "audit" && "$AI_ASSESS" == "true" ]]; then
                     echo "**Result: ℹ️ INFORMATIONAL** — AI augmentation is enabled, so the SLA check is audit-only (${VIOLATION_COUNT} violation(s) reported); enforcement is delegated to the AI assessment below."
                   else
                     echo "**Result: ℹ️ INFORMATIONAL** — gate is in audit mode; ${VIOLATION_COUNT} violation(s) reported, none blocking."
                   fi ;;
  esac
} >> "$GITHUB_STEP_SUMMARY"

# --- Outputs ------------------------------------------------------------------
{
  echo "result=${RESULT}"
  echo "violation-count=${VIOLATION_COUNT}"
  echo "enforced-violation-count=${ENFORCED_COUNT}"
  echo "audited-commit=${GITHUB_SHA}"
  echo "report-path=${REPORT_PATH}"
} >> "$GITHUB_OUTPUT"

echo "Result: ${RESULT} | open=${TOTAL_OPEN} violations=${VIOLATION_COUNT} enforced=${ENFORCED_COUNT}"

# --- Optional AI risk assessment ---------------------------------------------
# When enabled, ask a GitHub Models LLM to weigh the open alerts together with
# their SLA status (age, SLA, days over) and CISA KEV known-exploited data, and
# emit an overall risk verdict. Enabling AI augmentation also downgrades the
# deterministic SLA gate to audit-only (see the RESULT computation above): the
# raw SLA count no longer fails the job, and enforcement is delegated to this AI
# verdict, which already folds SLA status, KEV, and severity into its decision.
# The verdict fails the job when it meets the `ai-fail-on` threshold (still only
# in `enforce` mode). AI_ENFORCE_FAIL records that outcome for the final gate.
AI_ENFORCE_FAIL=0
if [[ "$AI_ASSESS" == "true" ]]; then
  echo "AI risk assessment enabled; weighing open alerts (with SLA status) via GitHub Models (${AI_MODEL})..."

  # --- Fetch CISA KEV catalog (known-exploited amplifier) --------------------
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  KEV_FILE=$(KEV_CACHE_DIR="${KEV_CACHE_DIR:-}" bash "${SCRIPT_DIR}/kev_catalog.sh")
  KEV_CATALOG_SIZE=$(jq 'length' "$KEV_FILE")
  echo "Loaded ${KEV_CATALOG_SIZE} CISA KEV catalog entries."

  AI_SEV_RANK='{"critical":0,"high":1,"medium":2,"low":3}'

  # Re-shape the SLA-evaluated alerts into a compact, model-friendly form and
  # enrich each with CISA KEV data, keyed on the real CVE (empty CVEs never match).
  # Sort KEV-first, then severity, then most-over-SLA so any truncation to fit the
  # token budget drops the least important detail. The map is large, so it is fed
  # to jq via --slurpfile (argv would overflow ARG_MAX).
  AI_ALERTS=$(jq -c --argjson rank "$AI_SEV_RANK" --slurpfile kevwrap "$KEV_FILE" '
    ($kevwrap[0] // {}) as $kev |
    [ .[] | {
        alert_number: .alert_number,
        package: .package,
        ecosystem: .ecosystem,
        manifest: .manifest_path,
        advisory: .cve_id,
        cve: .cve,
        severity: .severity,
        cve_published_at: .cve_published_at,
        age_days: .age_days,
        sla_days: .sla_days,
        days_over_sla: .days_over_sla,
        in_violation: .in_violation,
        first_patched_version: .first_patched_version,
        known_exploited: (.cve != "" and ($kev[.cve] != null)),
        kev: (if .cve != "" then $kev[.cve] else null end),
        url: .alert_url
      } ]
    | sort_by([(.known_exploited | not), ($rank[.severity] // 5), -(.days_over_sla)])' <<< "$EVALUATED")
  # Keep the file when it lives in the cache dir so actions/cache can persist it.
  [[ -z "${KEV_CACHE_DIR:-}" ]] && rm -f "$KEV_FILE"

  # Distinct CVEs across the open alerts that are in the KEV catalog (exploited).
  KEV_MATCHED=$(jq '[ .[] | select(.known_exploited) | .cve ] | unique | length' <<< "$AI_ALERTS")

  # Compensating controls text fed to the model and recorded for audit.
  MITIGATIONS_TEXT="$MITIGATIONS"
  [[ -z "${MITIGATIONS_TEXT//[[:space:]]/}" ]] && MITIGATIONS_TEXT="None specified."
  MITIGATIONS_CELL=$(printf '%s' "$MITIGATIONS_TEXT" | tr '\n' ' ' | sed 's/|/\\|/g')

  # Detail actually sent to the model (set by the sizing loop below); defaults cover
  # the no-open-alerts path.
  AI_SENT="[]"
  AI_SENT_N=0
  AI_TRUNC=0

  if [[ "$TOTAL_OPEN" -eq 0 ]]; then
    echo "No open Dependabot alerts; recording a clean AI verdict without calling the model."
    VERDICT=$(jq -nc '{
      risk_level: "minimal",
      recommendation: "go",
      confidence: "high",
      summary: "No open Dependabot alerts were found for this commit.",
      key_risks: [],
      recommended_mitigations: []
    }')
    AI_MODEL_USED="none (no open alerts)"
  else
    # --- Structured-output schema (identical shape to Risk AI Advisor) --------
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

    SYSTEM_PROMPT="You are a principal application security engineer acting as a release gatekeeper. You assess whether a software build is safe to release to its target deployment environment by reasoning over open dependency (Dependabot) vulnerabilities, each annotated with its remediation-SLA status. The target deployment environment is: \"${DEPLOYMENT_ENVIRONMENT}\" (additional detail may appear in the user message). Calibrate your assessment to that environment's exposure and blast radius rather than assuming it is internet-facing: weigh exploitability given who can actually reach the affected dependency (the public internet for an internet-facing production site, versus a restricted internal network or an isolated pre-production environment), severity, and whether fixes are available. Each finding carries SLA fields: \"sla_days\" (the remediation deadline for its severity, measured from the CVE published date), \"age_days\" (how long it has been open), \"days_over_sla\" (how far past the deadline, 0 if within SLA), and \"in_violation\" (true when past the deadline). Treat an SLA breach as an escalating factor: a finding in violation — especially one many days over its SLA — signals overdue, accumulating risk and should push the risk level and recommendation upward, more sharply the larger \"days_over_sla\" is and the more severe the finding. Findings may also be annotated with \"known_exploited\": true and a \"kev\" object: these CVEs appear in the CISA Known Exploited Vulnerabilities (KEV) catalog, meaning active in-the-wild exploitation is confirmed. Treat any KEV-listed vulnerability as a strong escalating factor — it should push the risk level and recommendation decisively toward blocking, most sharply for internet-facing environments, when knownRansomwareCampaignUse is 'Known', or when a fix is available. KEV status and SLA breach are amplifiers, not filters: they raise the priority of matching findings but do NOT mean other findings are unimportant. You must still consider and surface non-KEV, within-SLA vulnerabilities that a security reviewer would care about — e.g. critical/high-severity issues, findings reachable in the target environment, and vulnerabilities with available fixes. Be decisive and concise. Reserve 'critical' for issues that are likely exploitable in the target environment with serious impact (for internet-facing deployments, remotely exploitable and KEV-listed vulnerabilities are prime candidates). The user message may list compensating controls already deployed in front of the application (for example a WAF, load balancer, CDN with DDoS protection, network isolation, or rate limiting). When controls are listed, factor them into your exploitability and blast-radius reasoning — they can lower the practical risk of a finding — but treat them as risk-reducing, NOT risk-eliminating: controls can be misconfigured, bypassed, or simply not cover a given finding, so never downgrade a critical, KEV-listed, or badly SLA-breached vulnerability to negligible solely because a mitigation is present. Note in why_it_matters when a listed control materially changed your assessment. Output only what the provided JSON schema allows."

    # --- Size the request to the model's input-token limit ------------------
    # GitHub Models caps the request body; an HTTP 413 kills the run. Slim each
    # alert and shrink how many are sent until the serialized request fits a
    # conservative char budget (~4 chars/token). Alerts are pre-sorted KEV-/
    # severity-/over-SLA-first, so trimming drops the least important detail.
    REQ_CHAR_BUDGET=24000   # ~6000 tokens, safely under the 8000-token cap
    TEXT_MAX=280            # cap on per-alert free-text

    slim_alerts() {  # $1 = max items to keep
      jq -c --argjson n "$1" --argjson t "$TEXT_MAX" '[ .[0:$n][] | {
          alert_number, severity, package, ecosystem, manifest, advisory, cve,
          age_days, sla_days, days_over_sla, in_violation,
          first_patched_version, known_exploited,
          kev: (if .kev != null then { cve: .kev.cve, known_ransomware: .kev.known_ransomware, due_date: .kev.due_date } else null end),
          url
        } ]' <<< "$AI_ALERTS"
    }

    N_SENT="$MAX_ALERTS"
    while :; do
      AI_SENT=$(slim_alerts "$N_SENT")
      AI_SENT_N=$(jq 'length' <<< "$AI_SENT")
      AI_TRUNC=$(( TOTAL_OPEN > AI_SENT_N ? TOTAL_OPEN - AI_SENT_N : 0 ))

      USER_PROMPT=$(jq -nr \
        --arg ctx "$APP_CONTEXT" \
        --arg env "$DEPLOYMENT_ENVIRONMENT" \
        --arg repo "$REPOSITORY" \
        --arg sha "${GITHUB_SHA:-n/a}" \
        --arg mode "$MODE" \
        --argjson alerts "$AI_SENT" \
        --argjson total "$TOTAL_OPEN" \
        --argjson trunc "$AI_TRUNC" \
        --argjson slas "$SLAS" \
        --argjson violations "$VIOLATION_COUNT" \
        --argjson enforced "$ENFORCED_COUNT" \
        --argjson kev_size "$KEV_CATALOG_SIZE" \
        --argjson kev_matched "$KEV_MATCHED" \
        --arg mitig "$MITIGATIONS_TEXT" \
        '"Release context: \($ctx)\n" +
         "Deployment environment: \($env)\n" +
         "Compensating controls already in place: \($mitig)\n" +
         "Repository: \($repo)\nCommit: \($sha)\nSLA gate mode: \($mode)\n\n" +
         "Remediation SLA policy (days from CVE published date): critical=\($slas.critical), high=\($slas.high), medium=\($slas.medium), low=\($slas.low).\n" +
         "Open Dependabot alerts: \($total) (showing \($alerts | length), \($trunc) omitted for brevity).\n" +
         "Alerts over their SLA: \($violations) total, \($enforced) in enforced severities.\n" +
         "CISA KEV catalog: \($kev_size) entries loaded; \($kev_matched) distinct CVE(s) across the open alerts match the KEV catalog (actively exploited in the wild). Findings are annotated with \"known_exploited\" and a \"kev\" object when matched.\n\n" +
         "Dependabot findings with SLA status (JSON):\n" + ($alerts | tojson) + "\n\n" +
         "Assess the OVERALL risk of releasing this build to the environment described above. Give decisive weight to any KEV-listed (known_exploited) vulnerability and to findings badly past their remediation SLA (large days_over_sla). Return your verdict per the required schema. In key_risks, list ALL release-relevant issues a reviewer should weigh — not only KEV-matched or SLA-breached ones. Order key_risks by importance (KEV-listed, critical, and most-over-SLA first), set source to \"dependabot\", and call out KEV/known-exploited status and SLA breach (days_over_sla) in why_it_matters when applicable. In recommended_mitigations, give concrete, prioritized actions, remediating known-exploited and SLA-breached vulnerabilities first."')

      REQ=$(jq -nc \
        --arg model "$AI_MODEL" \
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
          # Verdicts with several KEV/critical findings and detailed why_it_matters
          # text run long; 1500 tokens truncated the JSON mid-string (unparseable).
          # Give the completion ample room — the output is bounded by the schema.
          max_tokens: 4000
        }')

      # Fits, or we're already at the minimum — stop shrinking.
      if [[ "${#REQ}" -le "$REQ_CHAR_BUDGET" || "$N_SENT" -le 1 ]]; then
        break
      fi
      N_SENT=$(( N_SENT / 2 ))
      (( N_SENT < 1 )) && N_SENT=1
    done

    if [[ "$AI_TRUNC" -gt 0 ]]; then
      echo "Trimmed alert detail to fit the model input limit: sending ${AI_SENT_N} alert(s) (${AI_TRUNC} omitted)."
    fi

    # Emit the exact prompt actually sent (all inputs resolved) to the workflow log
    # so the inference is auditable. Only public alert metadata + config inputs; no
    # tokens/secrets.
    echo "::group::Risk SLA Gate AI — model request: system prompt"
    echo "$SYSTEM_PROMPT"
    echo "::endgroup::"
    echo "::group::Risk SLA Gate AI — model request: user prompt (input values included)"
    echo "$USER_PROMPT"
    echo "::endgroup::"

    echo "Requesting risk assessment from GitHub Models (${AI_MODEL})..."
    RESP_FILE=$(mktemp)
    HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
      -X POST "https://models.github.ai/inference/chat/completions" \
      -H "Authorization: Bearer ${MODELS_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      -H "Content-Type: application/json" \
      -d "$REQ" || echo "000")

    if [[ "$HTTP_CODE" != "200" ]]; then
      echo "::error::GitHub Models inference failed (HTTP ${HTTP_CODE}). Ensure the calling job grants 'models: read' and the model id '${AI_MODEL}' is valid. Response: $(tr '\n' ' ' < "$RESP_FILE" | head -c 800)"
      rm -f "$RESP_FILE"
      exit 1
    fi

    echo "::group::Risk SLA Gate AI — model response: raw API body"
    jq . "$RESP_FILE" 2>/dev/null || cat "$RESP_FILE"
    echo "::endgroup::"

    CONTENT=$(jq -r '.choices[0].message.content // empty' < "$RESP_FILE")
    # finish_reason == "length" means the model hit max_tokens and the JSON was cut
    # off mid-stream, so it won't parse. Capture it before removing the response so
    # we can report the real cause instead of a generic parse failure.
    FINISH_REASON=$(jq -r '.choices[0].finish_reason // "unknown"' < "$RESP_FILE")
    rm -f "$RESP_FILE"
    if [[ -z "$CONTENT" ]]; then
      echo "::error::GitHub Models returned no content to parse."
      exit 1
    fi

    if ! VERDICT=$(jq -e . <<< "$CONTENT" 2>/dev/null); then
      if [[ "$FINISH_REASON" == "length" ]]; then
        echo "::error::The model's JSON verdict was truncated (finish_reason=length) before it could be completed, so it can't be parsed. This usually means too many/verbose key_risks for the output budget — lower 'max-alerts' to send fewer findings, or raise the max_tokens value in risk_sla_gate.sh. Raw (truncated) content: $(head -c 800 <<< "$CONTENT")"
      else
        echo "::error::Could not parse the model's JSON verdict (finish_reason=${FINISH_REASON}). Raw content: $(head -c 800 <<< "$CONTENT")"
      fi
      exit 1
    fi
    AI_MODEL_USED="$AI_MODEL"

    echo "::group::Risk SLA Gate AI — model response: verdict JSON"
    jq . <<< "$VERDICT"
    echo "::endgroup::"
  fi

  # --- Extract verdict fields ------------------------------------------------
  AI_RISK_LEVEL=$(jq -r '.risk_level' <<< "$VERDICT")
  AI_RECOMMENDATION=$(jq -r '.recommendation' <<< "$VERDICT")
  AI_CONFIDENCE=$(jq -r '.confidence' <<< "$VERDICT")
  AI_SUMMARY=$(jq -r '.summary' <<< "$VERDICT")

  # --- Determine AI gate result (fail-on is a severity THRESHOLD) -------------
  AI_LEVEL_RANK='{"critical":0,"high":1,"medium":2,"low":3,"minimal":4}'
  AI_FAIL_ON_COUNT=$(jq 'length' <<< "$AI_FAIL_ON_JSON")
  AI_THRESHOLD_LEVEL=""
  if [[ "$MODE" == "audit" ]]; then
    AI_RESULT="advisory"
    AI_THRESHOLD_LEVEL=""
  elif [[ "$AI_FAIL_ON_COUNT" -eq 0 ]]; then
    AI_RESULT="advisory"
  else
    # Lower rank = more severe. Threshold = least severe (max rank) level listed.
    AI_THRESHOLD_RANK=$(jq -r --argjson rank "$AI_LEVEL_RANK" '[ .[] | $rank[.] ] | max' <<< "$AI_FAIL_ON_JSON")
    AI_THRESHOLD_LEVEL=$(jq -rn --argjson rank "$AI_LEVEL_RANK" --argjson t "$AI_THRESHOLD_RANK" \
      '$rank | to_entries | map(select(.value == $t)) | .[0].key')
    AI_RISK_RANK=$(jq -nr --argjson rank "$AI_LEVEL_RANK" --arg r "$AI_RISK_LEVEL" '$rank[$r] // 99')
    if [[ "$AI_RISK_RANK" -le "$AI_THRESHOLD_RANK" ]]; then
      AI_RESULT="fail"
      AI_ENFORCE_FAIL=1
    else
      AI_RESULT="pass"
    fi
  fi

  # --- Merge the AI assessment into the existing compliance report ------------
  # Re-emit the single report file with an added ai_assessment section so the one
  # attested/uploaded report carries both the SLA audit and the AI verdict.
  AI_SECTION=$(jq -n \
    --arg model "$AI_MODEL_USED" \
    --arg deployment_environment "$DEPLOYMENT_ENVIRONMENT" \
    --arg app_context "$APP_CONTEXT" \
    --arg mitigations "$MITIGATIONS_TEXT" \
    --arg result "$AI_RESULT" \
    --argjson fail_on "$AI_FAIL_ON_JSON" \
    --argjson kev_catalog_size "$KEV_CATALOG_SIZE" \
    --argjson kev_matched "$KEV_MATCHED" \
    --argjson alerts_considered "$TOTAL_OPEN" \
    --argjson alerts_truncated "$AI_TRUNC" \
    --argjson verdict "$VERDICT" \
    '{
      model: $model,
      deployment_environment: $deployment_environment,
      app_context: $app_context,
      mitigations: $mitigations,
      result: $result,
      fail_on: $fail_on,
      kev_catalog_size: $kev_catalog_size,
      kev_matched: $kev_matched,
      alerts_considered: $alerts_considered,
      alerts_truncated: $alerts_truncated,
      verdict: $verdict
    }')
  AI_REPORT_TMP=$(mktemp)
  jq --argjson ai "$AI_SECTION" '. + {ai_assessment: $ai}' "$REPORT_PATH" > "$AI_REPORT_TMP" && mv "$AI_REPORT_TMP" "$REPORT_PATH"
  echo "AI assessment merged into ${REPORT_PATH}"

  # --- AI step summary section -----------------------------------------------
  ai_risk_emoji() {
    case "$1" in
      critical) echo "🟥" ;; high) echo "🟧" ;; medium) echo "🟨" ;;
      low) echo "🟩" ;; minimal) echo "✅" ;; *) echo "⬜" ;;
    esac
  }
  {
    echo ""
    echo "## 🤖 AI Risk Assessment"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Deployment environment | ${DEPLOYMENT_ENVIRONMENT} |"
    echo "| Compensating controls | ${MITIGATIONS_CELL} |"
    echo "| Model | \`${AI_MODEL_USED}\` |"
    echo "| 🚨 Known-exploited (CISA KEV) | ${KEV_MATCHED} |"
    echo ""
    if [[ "$KEV_MATCHED" -gt 0 ]]; then
      echo "> 🚨 **${KEV_MATCHED} known-exploited CVE(s) (CISA KEV) found in open Dependabot alerts** — confirmed in-the-wild exploitation; remediate before release."
      echo ""
      echo "| CVE | Package | Severity | Over SLA (d) | Ransomware | KEV due date |"
      echo "|---|---|---|---:|---|---|"
      jq -r '[ .[] | select(.known_exploited) ] | unique_by(.cve) | .[] | "| \(.cve) | \(.package) | \(.severity) | \(.days_over_sla) | \(.kev.known_ransomware // "Unknown") | \(.kev.due_date // "n/a") |"' <<< "$AI_ALERTS"
      echo ""
    fi
    echo "### $(ai_risk_emoji "$AI_RISK_LEVEL") Verdict: ${AI_RISK_LEVEL^^} — recommendation: \`${AI_RECOMMENDATION}\` (confidence: ${AI_CONFIDENCE})"
    echo ""
    echo "> ${AI_SUMMARY}"
    echo ""
    AI_KEY_RISK_COUNT=$(jq '.key_risks | length' <<< "$VERDICT")
    if [[ "$AI_KEY_RISK_COUNT" -gt 0 ]]; then
      echo "### Key risks (${AI_KEY_RISK_COUNT})"
      echo ""
      echo "| Severity | Source | Risk | Why it matters |"
      echo "|---|---|---|---|"
      jq -r '.key_risks[] | "| \(.severity) | \(.source) | \(.title) | \(.why_it_matters) |"' <<< "$VERDICT"
      echo ""
    fi
    AI_MIT_COUNT=$(jq '.recommended_mitigations | length' <<< "$VERDICT")
    if [[ "$AI_MIT_COUNT" -gt 0 ]]; then
      echo "### Recommended mitigations"
      echo ""
      jq -r '.recommended_mitigations[] | "- \(.)"' <<< "$VERDICT"
      echo ""
    fi
    case "$AI_RESULT" in
      advisory) if [[ "$MODE" == "audit" ]]; then
                   echo "**AI result: ℹ️ ADVISORY** — audit mode is active, so the AI assessment is reported only and never blocks the pipeline."
                 else
                   echo "**AI result: ℹ️ ADVISORY** — reporting only; no \`ai-fail-on\` threshold is set, so this never blocks."
                 fi ;;
      pass)     echo "**AI result: ✅ PASS** — AI risk level \`${AI_RISK_LEVEL}\` is below the \`ai-fail-on\` threshold (\`${AI_THRESHOLD_LEVEL}\` and above)." ;;
      fail)     echo "**AI result: ❌ FAIL** — AI risk level \`${AI_RISK_LEVEL}\` is at or above the \`ai-fail-on\` threshold (\`${AI_THRESHOLD_LEVEL}\` and above). Blocking this release." ;;
    esac
    if [[ "$AI_TRUNC" -gt 0 ]]; then
      echo ""
      echo "_Note: ${AI_TRUNC} alert(s) were omitted from the model prompt to stay within the \`max-alerts\` cap (${MAX_ALERTS}) and the model's input-token limit; the SLA tables above are complete._"
    fi
    # Record the exact prompt sent to the model in the summary for auditability.
    # Only present when a model call actually happened (the zero-alert path builds
    # no prompt). Collapsed so it does not crowd out the verdict; contains only
    # public alert metadata and config inputs — no tokens/secrets.
    if [[ -n "${SYSTEM_PROMPT:-}" ]]; then
      echo ""
      echo "<details><summary>🧾 Model prompt sent to <code>${AI_MODEL_USED}</code> (system + user)</summary>"
      echo ""
      echo "**System prompt**"
      echo ""
      echo '```text'
      echo "$SYSTEM_PROMPT"
      echo '```'
      echo ""
      echo "**User prompt** (resolved input values)"
      echo ""
      echo '```text'
      echo "$USER_PROMPT"
      echo '```'
      echo ""
      echo "</details>"
    fi
  } >> "$GITHUB_STEP_SUMMARY"

  # --- AI outputs ------------------------------------------------------------
  {
    echo "ai-result=${AI_RESULT}"
    echo "ai-risk-level=${AI_RISK_LEVEL}"
    echo "ai-recommendation=${AI_RECOMMENDATION}"
    echo "kev-matched=${KEV_MATCHED}"
    echo "ai-summary=$(tr '\n' ' ' <<< "$AI_SUMMARY" | head -c 500)"
  } >> "$GITHUB_OUTPUT"

  echo "AI verdict: ${AI_RISK_LEVEL} | recommendation=${AI_RECOMMENDATION} | ai-result=${AI_RESULT} | kev=${KEV_MATCHED}"
fi

# --- Enforcement --------------------------------------------------------------
# What can fail the job depends on whether AI augmentation is enabled:
#   * AI OFF (AI_ASSESS!=true): the deterministic SLA gate enforces — a violation
#     in an enforced severity fails the job in `enforce` mode.
#   * AI ON (AI_ASSESS==true): the SLA gate is audit-only and never fails the job
#     on its own; enforcement is delegated to the AI verdict (ai-fail-on), which
#     already accounts for SLA status. Either way both results are reported above.
SLA_ENFORCE_FAIL=0
if [[ "$AI_ASSESS" != "true" && "$MODE" == "enforce" && "$ENFORCED_COUNT" -gt 0 ]]; then
  SLA_ENFORCE_FAIL=1
  echo "::error::Risk SLA Gate failed: ${ENFORCED_COUNT} Dependabot alert(s) in enforced severities ($(jq -r 'join(", ")' <<< "$ENFORCE_JSON")) exceed their remediation SLA. See the job summary and compliance report for details."
fi
if [[ "$MODE" != "audit" && "$AI_ENFORCE_FAIL" -eq 1 ]]; then
  echo "::error::Risk SLA Gate AI assessment failed: assessed risk level '${AI_RISK_LEVEL}' meets the 'ai-fail-on' threshold. See the job summary and compliance report for details."
fi
if [[ "$SLA_ENFORCE_FAIL" -eq 1 || ( "$MODE" != "audit" && "$AI_ENFORCE_FAIL" -eq 1 ) ]]; then
  exit 1
fi