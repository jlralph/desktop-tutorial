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
MODE="${MODE:-inform}"
ENFORCE_SEVERITIES="${ENFORCE_SEVERITIES:-critical,high}"
REPORT_PATH="risk-sla-gate-report-${GITHUB_SHA}.json"

# --- Validate inputs --------------------------------------------------------
if [[ "$MODE" != "enforce" && "$MODE" != "inform" ]]; then
  echo "::error::Input 'mode' must be 'enforce' or 'inform' (got '${MODE}')."
  exit 1
fi

for var in SLA_CRITICAL SLA_HIGH SLA_MEDIUM SLA_LOW; do
  if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
    echo "::error::Input '${var}' must be a non-negative integer (got '${!var}')."
    exit 1
  fi
done

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
  --argjson slas "$SLAS" '
  def rank: {"critical": 0, "high": 1, "medium": 2, "low": 3};
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
        manifest_path: .dependency.manifest_path,
        cve_id: (.security_advisory.cve_id // .security_advisory.ghsa_id // "N/A"),
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
  | sort_by([(rank[.severity] // 4), -(.days_over_sla)])' <<< "$ALERTS")

VIOLATIONS=$(jq -c '[ .[] | select(.in_violation) ]' <<< "$EVALUATED")
TOTAL_OPEN=$(jq 'length' <<< "$EVALUATED")
VIOLATION_COUNT=$(jq 'length' <<< "$VIOLATIONS")
ENFORCED_COUNT=$(jq --argjson e "$ENFORCE_JSON" \
  '[ .[] | select(.severity as $s | $e | index($s)) ] | length' <<< "$VIOLATIONS")

if [[ "$MODE" == "inform" ]]; then
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
    informational) echo "**Result: ℹ️ INFORMATIONAL** — gate is in inform mode; ${VIOLATION_COUNT} violation(s) reported, none blocking." ;;
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

# --- Enforcement --------------------------------------------------------------
if [[ "$MODE" == "enforce" && "$ENFORCED_COUNT" -gt 0 ]]; then
  echo "::error::Risk SLA Gate failed: ${ENFORCED_COUNT} Dependabot alert(s) in enforced severities ($(jq -r 'join(", ")' <<< "$ENFORCE_JSON")) exceed their remediation SLA. See the job summary and compliance report for details."
  exit 1
fi