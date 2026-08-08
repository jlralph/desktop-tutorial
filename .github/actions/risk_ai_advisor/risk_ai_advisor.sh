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
AI_ENDPOINT="${AI_ENDPOINT:-https://models.github.ai/inference/chat/completions}"
AI_AUTH_SCHEME="${AI_AUTH_SCHEME:-bearer}"
DEPLOYMENT_ENVIRONMENT="${DEPLOYMENT_ENVIRONMENT:-production - public internet-facing}"
APP_CONTEXT="${APP_CONTEXT:-A build being released to a public-facing, internet-exposed website.}"
# Compensating controls (WAF, load balancer, etc.) selected for this run, if any.
MITIGATIONS="${MITIGATIONS:-}"
FAIL_ON="${FAIL_ON:-}"
MAX_ALERTS="${MAX_ALERTS:-75}"
# Which code-scanning tool's alerts to assess. Defaults to CodeQL so alerts from
# other SARIF-uploading scanners on the repo are excluded. Set to a different
# tool name to target that scanner, or to empty/"all" to include every tool.
CODE_SCANNING_TOOL="${CODE_SCANNING_TOOL:-CodeQL}"
REPORT_PATH="risk-ai-advisor-report-${GITHUB_SHA:-local}.json"

VALID_LEVELS="critical high medium low minimal"

# --- Validate inputs --------------------------------------------------------
if ! [[ "$MAX_ALERTS" =~ ^[0-9]+$ ]]; then
  echo "::error::Input 'max-alerts' must be a non-negative integer (got '${MAX_ALERTS}')."
  exit 1
fi

AI_AUTH_SCHEME=$(printf '%s' "$AI_AUTH_SCHEME" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
if [[ "$AI_AUTH_SCHEME" != "bearer" && "$AI_AUTH_SCHEME" != "api-key" ]]; then
  echo "::error::Input 'ai-auth-scheme' must be 'bearer' or 'api-key' (got '${AI_AUTH_SCHEME}')."
  exit 1
fi
if [[ ! "$AI_ENDPOINT" =~ ^https:// ]]; then
  echo "::error::Input 'ai-endpoint' must be an https:// URL (got '${AI_ENDPOINT}'). Refusing to send a bearer token over an insecure or non-HTTP(S) scheme."
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
# runs on whatever signal it can read. Writes "ok" or "fail" to the status file
# ($4) so the caller can distinguish "no alerts" from "couldn't read alerts".
fetch_alerts() {
  local path="$1" token="$2" name="$3" statusfile="$4" raw err
  err="$(mktemp)"
  if raw=$(GH_TOKEN="$token" gh api --paginate \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$path" 2>"$err"); then
    echo "ok" > "$statusfile"
    jq -s 'add // []' <<< "$raw"
  else
    echo "fail" > "$statusfile"
    echo "::warning::Could not read ${name} for ${REPOSITORY}; proceeding without it. Detail: $(tr '\n' ' ' < "$err")" >&2
    echo "[]"
  fi
  rm -f "$err"
}

echo "Collecting open security alerts for ${REPOSITORY} (commit ${GITHUB_SHA:-n/a})..."
CODEQL_STATUS_FILE=$(mktemp)
DEPENDABOT_STATUS_FILE=$(mktemp)
# Restrict code-scanning alerts to one tool (CodeQL by default) so findings from
# other SARIF-uploading scanners aren't mixed in. An empty value (or "all")
# disables the filter and pulls every tool's alerts. The tool name is URL-encoded.
CODE_SCANNING_TOOL_QUERY=""
CODE_SCANNING_LABEL="code-scanning alerts (all tools)"
if [[ -n "$CODE_SCANNING_TOOL" && "${CODE_SCANNING_TOOL,,}" != "all" ]]; then
  CODE_SCANNING_TOOL_QUERY="&tool_name=$(jq -rn --arg t "$CODE_SCANNING_TOOL" '$t | @uri')"
  CODE_SCANNING_LABEL="${CODE_SCANNING_TOOL} code-scanning alerts"
fi
CODEQL_RAW=$(fetch_alerts "/repos/${REPOSITORY}/code-scanning/alerts?state=open&per_page=100${CODE_SCANNING_TOOL_QUERY}" "$GH_TOKEN" "$CODE_SCANNING_LABEL" "$CODEQL_STATUS_FILE")
DEPENDABOT_RAW=$(fetch_alerts "/repos/${REPOSITORY}/dependabot/alerts?state=open&per_page=100" "$DEPENDABOT_TOKEN" "Dependabot alerts" "$DEPENDABOT_STATUS_FILE")
CODEQL_READABLE=$(cat "$CODEQL_STATUS_FILE")
DEPENDABOT_READABLE=$(cat "$DEPENDABOT_STATUS_FILE")
rm -f "$CODEQL_STATUS_FILE" "$DEPENDABOT_STATUS_FILE"

# --- Fetch CISA KEV catalog -------------------------------------------------
# The CISA Known Exploited Vulnerabilities (KEV) catalog lists CVEs with
# evidence of active, in-the-wild exploitation. A Dependabot alert whose CVE
# appears here is a major risk amplifier (proven exploitation, often with a
# federal remediation due date), so we annotate matches and tell the model to
# weigh them heavily. A network/parse failure degrades to an empty catalog so
# the advisor still runs on the rest of the signal.
#
# The fetch/parse/cache logic lives in kev_catalog.sh, which builds the compact
# CVE -> KEV-record map and prints the map file path. The map is large (1600+
# entries) and is fed to jq via --slurpfile rather than --argjson below: that
# big a value in argv overflows ARG_MAX ("Argument list too long"). Here-strings
# (<<<) go to stdin, so reading its length is unaffected.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEV_FILE=$(KEV_CACHE_DIR="${KEV_CACHE_DIR:-}" bash "${SCRIPT_DIR}/kev_catalog.sh")
KEV_CATALOG_SIZE=$(jq 'length' "$KEV_FILE")
echo "Loaded ${KEV_CATALOG_SIZE} CISA KEV catalog entries."

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

# Dependabot alerts are enriched with CISA KEV data: any whose CVE is in the
# catalog is flagged known_exploited and carries the KEV record. Known-exploited
# alerts sort first so they survive max-alerts truncation.
#
# After sorting, DUPLICATE alerts for the same vulnerability are collapsed to a
# single representative: the same CVE can surface as several open alerts (e.g. the
# same package reported under two manifest-path spellings), which would otherwise
# send the model the same finding multiple times — wasting the token budget and
# over-weighting it. Dedup is keyed on the CVE, falling back to the advisory
# (GHSA) id when there is no CVE, and to the alert number when neither exists so
# genuinely distinct advisories are never merged. The array is deduped in place,
# so the counts, the summary, and the model list all see each vulnerability once.
# Because the array is pre-sorted KEV-/severity-first, the kept representative is
# the highest-priority instance of each vulnerability.
DEPENDABOT=$(jq -c --argjson rank "$SEV_RANK" --slurpfile kevwrap "$KEV_FILE" '
  ($kevwrap[0] // {}) as $kev |
  [ .[] | (.security_advisory.cve_id // "") as $cve | {
      number: .number,
      severity: ((.security_vulnerability.severity // .security_advisory.severity // "unknown") | ascii_downcase),
      package: (.dependency.package.name // "unknown"),
      ecosystem: (.dependency.package.ecosystem // "unknown"),
      manifest: (.dependency.manifest_path // "n/a"),
      advisory: (.security_advisory.cve_id // .security_advisory.ghsa_id // "N/A"),
      cve: $cve,
      summary: (.security_advisory.summary // ""),
      first_patched_version: (.security_vulnerability.first_patched_version.identifier // "none"),
      known_exploited: ($cve != "" and ($kev[$cve] != null)),
      kev: (if $cve != "" then $kev[$cve] else null end),
      url: .html_url
    } ]
  | sort_by([(.known_exploited | not), ($rank[.severity] // 5)])
  | reduce .[] as $x ({seen: {}, out: []};
      ( if $x.cve != "" then "cve:" + $x.cve
        elif $x.advisory != "N/A" then "adv:" + $x.advisory
        else "num:" + ($x.number | tostring) end ) as $k
      | if .seen[$k] then . else (.seen[$k] = true) | (.out += [$x]) end)
  | .out' <<< "$DEPENDABOT_RAW")
# Keep the file when it lives in the cache dir so actions/cache can persist it.
[[ -z "${KEV_CACHE_DIR:-}" ]] && rm -f "$KEV_FILE"

CODEQL_OPEN=$(jq 'length' <<< "$CODEQL")
DEPENDABOT_OPEN=$(jq 'length' <<< "$DEPENDABOT")
TOTAL_OPEN=$(( CODEQL_OPEN + DEPENDABOT_OPEN ))

# How many duplicate Dependabot alerts were collapsed above (fetched minus the
# distinct set now in $DEPENDABOT). Surfaced in the log, summary, and report.
DEPENDABOT_FETCHED=$(jq 'length' <<< "$DEPENDABOT_RAW")
DEPENDABOT_DUPES=$(( DEPENDABOT_FETCHED > DEPENDABOT_OPEN ? DEPENDABOT_FETCHED - DEPENDABOT_OPEN : 0 ))
[[ "$DEPENDABOT_DUPES" -gt 0 ]] && echo "Collapsed ${DEPENDABOT_DUPES} duplicate Dependabot alert(s) sharing a CVE/advisory before assessment; ${DEPENDABOT_OPEN} distinct vulnerabilities remain."

# How many distinct CVEs across the open Dependabot alerts are in the CISA KEV
# catalog (actively exploited). Counted distinct-by-CVE so it matches the deduped
# KEV table below (several alerts can share one CVE).
KEV_MATCHED=$(jq '[ .[] | select(.known_exploited) | .cve ] | unique | length' <<< "$DEPENDABOT")

# Severity tallies (for the summary table; computed over all alerts, not the truncated set).
count_sev() { jq --arg s "$1" '[ .[] | select(.severity == $s) ] | length' <<< "$2"; }

# Per-type detail/truncation sent to the model. The actual values are computed in
# the request-sizing loop below (which shrinks the payload to fit the model's
# input-token limit); these defaults cover the no-open-alerts path.
CODEQL_SENT="[]"
DEPENDABOT_SENT="[]"
CODEQL_TRUNC=0
DEPENDABOT_TRUNC=0

NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Compensating controls text fed to the model and recorded for audit. An empty
# (or whitespace-only) selection reads as "None specified.".
MITIGATIONS_TEXT="$MITIGATIONS"
[[ -z "${MITIGATIONS_TEXT//[[:space:]]/}" ]] && MITIGATIONS_TEXT="None specified."
# Single-line, pipe-escaped form so it renders cleanly in the Markdown summary cell.
MITIGATIONS_CELL=$(printf '%s' "$MITIGATIONS_TEXT" | tr '\n' ' ' | sed 's/|/\\|/g')
# Same single-line, pipe-escaped treatment for the context cells in the summary twisty.
APP_CONTEXT_CELL=$(printf '%s' "$APP_CONTEXT" | tr '\n' ' ' | sed 's/|/\\|/g')
DEPLOYMENT_ENVIRONMENT_CELL=$(printf '%s' "$DEPLOYMENT_ENVIRONMENT" | tr '\n' ' ' | sed 's/|/\\|/g')

# Captured for the step-summary twisty and the model-I/O attestation record.
# Populated when the model is called; left as placeholders on the no-alerts path.
SYSTEM_PROMPT=""
USER_PROMPT=""
RAW_RESPONSE=""

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

  SYSTEM_PROMPT="You are a principal application security engineer acting as a release gatekeeper. You assess whether a software build is safe to release to its target deployment environment by reasoning over open static-analysis (CodeQL) findings and open dependency (Dependabot) vulnerabilities. The target deployment environment is: \"${DEPLOYMENT_ENVIRONMENT}\" (additional detail may appear in the user message). Calibrate your assessment to that environment's exposure and blast radius rather than assuming it is internet-facing: weigh exploitability given who can actually reach the affected code/dependency (the public internet for an internet-facing production site, versus a restricted internal network or an isolated pre-production environment), the exposure of the affected component, severity, and whether fixes are available. A remotely, internet-exploitable vulnerability is far more urgent for an internet-facing production deployment than for an internal-only or non-production one, so adjust the risk level and recommendation accordingly — while never dismissing issues that remain reachable in the stated environment or that would gate promotion to production. Dependabot findings may be annotated with \"known_exploited\": true and a \"kev\" object: these CVEs appear in the CISA Known Exploited Vulnerabilities (KEV) catalog, meaning active in-the-wild exploitation is confirmed. Treat any KEV-listed vulnerability as a strong escalating factor — it should push the risk level and recommendation decisively toward blocking, most sharply for internet-facing environments, when knownRansomwareCampaignUse is 'Known', or when a fix is available. KEV status is an amplifier, not a filter: it raises the priority of matching findings but does NOT mean other findings are unimportant. You must still consider and surface non-KEV vulnerabilities that a security reviewer would care about — e.g. critical/high-severity issues, findings reachable in the target environment, and vulnerabilities with available fixes — even when KEV matches exist. Be decisive and concise. Reserve 'critical' for issues that are likely exploitable in the target environment with serious impact (for internet-facing deployments, remotely exploitable and KEV-listed vulnerabilities are prime candidates). The user message may list compensating controls already deployed in front of the application (for example a WAF, load balancer, CDN with DDoS protection, network isolation, or rate limiting). When controls are listed, factor them into your exploitability and blast-radius reasoning — they can lower the practical risk of a finding (e.g. network isolation limits who can reach it, a WAF can impede some injection or exploitation attempts, rate limiting blunts brute-force and some DoS) — but treat them as risk-reducing, NOT risk-eliminating: controls can be misconfigured, bypassed, or simply not cover a given finding, so never downgrade a critical, KEV-listed, or clearly reachable vulnerability to negligible solely because a mitigation is present. Note in why_it_matters when a listed control materially changed your assessment. Output only what the provided JSON schema allows."

  # --- Size the request to the model's input-token limit ------------------
  # GitHub Models caps the request body (e.g. gpt-4.1 allows ~8000 input
  # tokens), and an HTTP 413 "tokens_limit_reached" kills the run. The alert
  # detail is the variable part, so we (1) slim each alert to its essential
  # fields with long free-text truncated, and (2) shrink how many alerts we send
  # until the serialized request fits a conservative character budget
  # (~4 chars/token). Alerts are pre-sorted KEV-/severity-first, so trimming
  # drops the least important detail. Counts are always reported in full.
  REQ_CHAR_BUDGET=24000   # ~6000 tokens, safely under the 8000-token cap
  TEXT_MAX=280            # cap on per-alert free-text (description/summary)

  slim_codeql() {  # $1 = max items to keep
    jq -c --argjson n "$1" --argjson t "$TEXT_MAX" '[ .[0:$n][] | {
        number, rule_id, name, severity,
        description: ((.description // "") | if length > $t then .[0:$t] + "…" else . end),
        file, tool, url
      } ]' <<< "$CODEQL"
  }
  slim_dependabot() {  # $1 = max items to keep
    jq -c --argjson n "$1" --argjson t "$TEXT_MAX" '[ .[0:$n][] | {
        number, severity, package, ecosystem, manifest, advisory, cve,
        summary: ((.summary // "") | if length > $t then .[0:$t] + "…" else . end),
        first_patched_version, known_exploited,
        kev: (if .kev != null then { cve: .kev.cve, known_ransomware: .kev.known_ransomware, due_date: .kev.due_date } else null end),
        url
      } ]' <<< "$DEPENDABOT"
  }

  N_SENT="$MAX_ALERTS"
  while :; do
    CODEQL_SENT=$(slim_codeql "$N_SENT")
    DEPENDABOT_SENT=$(slim_dependabot "$N_SENT")
    CODEQL_SENT_N=$(jq 'length' <<< "$CODEQL_SENT")
    DEPENDABOT_SENT_N=$(jq 'length' <<< "$DEPENDABOT_SENT")
    CODEQL_TRUNC=$(( CODEQL_OPEN > CODEQL_SENT_N ? CODEQL_OPEN - CODEQL_SENT_N : 0 ))
    DEPENDABOT_TRUNC=$(( DEPENDABOT_OPEN > DEPENDABOT_SENT_N ? DEPENDABOT_OPEN - DEPENDABOT_SENT_N : 0 ))

    USER_PROMPT=$(jq -nr \
      --arg ctx "$APP_CONTEXT" \
      --arg env "$DEPLOYMENT_ENVIRONMENT" \
      --arg repo "$REPOSITORY" \
      --arg sha "${GITHUB_SHA:-n/a}" \
      --argjson codeql "$CODEQL_SENT" \
      --argjson dependabot "$DEPENDABOT_SENT" \
      --argjson codeql_total "$CODEQL_OPEN" \
      --argjson dependabot_total "$DEPENDABOT_OPEN" \
      --argjson codeql_trunc "$CODEQL_TRUNC" \
      --argjson dependabot_trunc "$DEPENDABOT_TRUNC" \
      --argjson kev_size "$KEV_CATALOG_SIZE" \
      --argjson kev_matched "$KEV_MATCHED" \
      --arg mitig "$MITIGATIONS_TEXT" \
      '"Release context: \($ctx)\n" +
       "Deployment environment: \($env)\n" +
       "Compensating controls already in place: \($mitig)\n" +
       "Repository: \($repo)\nCommit: \($sha)\n\n" +
       "Open CodeQL alerts: \($codeql_total) (showing \($codeql | length), \($codeql_trunc) omitted for brevity).\n" +
       "Open Dependabot alerts: \($dependabot_total) (showing \($dependabot | length), \($dependabot_trunc) omitted for brevity).\n" +
       "CISA KEV catalog: \($kev_size) entries loaded; \($kev_matched) distinct CVE(s) across the open Dependabot alerts match the KEV catalog (actively exploited in the wild). Dependabot findings are annotated with \"known_exploited\" and a \"kev\" object when matched.\n\n" +
       "CodeQL findings (JSON):\n" + ($codeql | tojson) + "\n\n" +
       "Dependabot findings (JSON):\n" + ($dependabot | tojson) + "\n\n" +
       "Assess the OVERALL risk of releasing this build to the public-facing site described above. Give decisive weight to any KEV-listed (known_exploited) vulnerability. Return your verdict per the required schema. In key_risks, list ALL release-relevant issues a reviewer should weigh — not only KEV-matched ones. Always include other serious findings (critical/high severity, internet-reachable CodeQL findings, and notable Dependabot vulnerabilities) alongside any KEV matches; do not drop them just because a KEV match exists. Order key_risks by importance (KEV-listed and critical first), set source to \"codeql\" or \"dependabot\", and call out KEV/known-exploited status in why_it_matters when applicable. In recommended_mitigations, give concrete, prioritized actions, remediating known-exploited vulnerabilities first."')

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
        max_tokens: 4096
      }')

    # Fits, or we're already down to the minimum we can send — stop shrinking.
    if [[ "${#REQ}" -le "$REQ_CHAR_BUDGET" || "$N_SENT" -le 1 ]]; then
      break
    fi
    N_SENT=$(( N_SENT / 2 ))
    (( N_SENT < 1 )) && N_SENT=1
  done

  if [[ "$CODEQL_TRUNC" -gt 0 || "$DEPENDABOT_TRUNC" -gt 0 ]]; then
    echo "Trimmed alert detail to fit the model input limit: sending ${CODEQL_SENT_N} CodeQL + ${DEPENDABOT_SENT_N} Dependabot alert(s) (${CODEQL_TRUNC} + ${DEPENDABOT_TRUNC} omitted)."
  fi

  # Emit the exact prompt actually sent — with all input values resolved — to the
  # workflow log so the inference is auditable. Wrapped in collapsible ::group::
  # sections to keep the log readable. (Contains only public alert metadata and
  # config inputs, no tokens/secrets.)
  echo "::group::Risk AI Advisor — model request: system prompt"
  echo "$SYSTEM_PROMPT"
  echo "::endgroup::"
  echo "::group::Risk AI Advisor — model request: user prompt (input values included)"
  echo "$USER_PROMPT"
  echo "::endgroup::"

  echo "Requesting risk assessment from ${AI_ENDPOINT} (model=${MODEL})..."
  RESP_FILE=$(mktemp)
  if [[ "$AI_AUTH_SCHEME" == "api-key" ]]; then
    AUTH_HEADER="api-key: ${MODELS_TOKEN}"
  else
    AUTH_HEADER="Authorization: Bearer ${MODELS_TOKEN}"
  fi
  HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
    -X POST "$AI_ENDPOINT" \
    -H "$AUTH_HEADER" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "$REQ" || echo "000")

  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "::error::AI inference request to '${AI_ENDPOINT}' failed (HTTP ${HTTP_CODE}). Check 'ai-endpoint', that the 'models-token' is valid for that endpoint, and that model id '${MODEL}' is valid there. GitHub Models was retired on 2026-07-30 — set 'ai-endpoint' to another OpenAI-compatible provider (see action inputs). Response: $(tr '\n' ' ' < "$RESP_FILE" | head -c 800)"
    rm -f "$RESP_FILE"
    exit 1
  fi

  # Capture the raw HTTP response body for the audit record and step-summary
  # twisty, then log the full body (choices, usage, etc.) so the complete
  # inference is auditable from the run. Pretty-printed when valid JSON, otherwise
  # emitted verbatim. No secrets are present in the response body.
  RAW_RESPONSE=$(cat "$RESP_FILE")
  echo "::group::Risk AI Advisor — model response: raw API body"
  jq . "$RESP_FILE" 2>/dev/null || cat "$RESP_FILE"
  echo "::endgroup::"

  CONTENT=$(jq -r '.choices[0].message.content // empty' < "$RESP_FILE")
  rm -f "$RESP_FILE"
  if [[ -z "$CONTENT" ]]; then
    echo "::error::GitHub Models returned no content to parse."
    exit 1
  fi

  # Some models wrap their JSON in a markdown code fence (```json ... ```).
  # Remove any lines that are purely a fence marker so jq can parse the content.
  CONTENT=$(sed '/^```/d' <<< "$CONTENT")

  if ! VERDICT=$(jq -e . <<< "$CONTENT" 2>/dev/null); then
    echo "::error::Could not parse the model's JSON verdict. Raw content: $(head -c 800 <<< "$CONTENT")"
    exit 1
  fi
  MODEL_USED="$MODEL"

  # Log the model's raw output (the verdict JSON) so it's auditable from the run.
  echo "::group::Risk AI Advisor — model response: verdict JSON"
  jq . <<< "$VERDICT"
  echo "::endgroup::"
fi

# --- Extract verdict fields --------------------------------------------------
RISK_LEVEL=$(jq -r '.risk_level' <<< "$VERDICT")
RECOMMENDATION=$(jq -r '.recommendation' <<< "$VERDICT")
CONFIDENCE=$(jq -r '.confidence' <<< "$VERDICT")
SUMMARY=$(jq -r '.summary' <<< "$VERDICT")

# --- Determine gate result ---------------------------------------------------
# fail-on is a severity THRESHOLD, not an exact-match list: the job fails when the
# verdict's risk level is at or above the threshold. So fail-on "high" fails on
# high and critical; "medium" fails on medium, high, and critical; and so on. When
# several levels are listed, the least severe one is used as the threshold (most
# inclusive), so any of the listed levels — and anything more severe — fails.
LEVEL_RANK='{"critical":0,"high":1,"medium":2,"low":3,"minimal":4}'
FAIL_ON_COUNT=$(jq 'length' <<< "$FAIL_ON_JSON")
if [[ "$FAIL_ON_COUNT" -eq 0 ]]; then
  RESULT="advisory"
else
  # Lower rank = more severe. Threshold = least severe (max rank) level listed.
  THRESHOLD_RANK=$(jq -r --argjson rank "$LEVEL_RANK" '[ .[] | $rank[.] ] | max' <<< "$FAIL_ON_JSON")
  THRESHOLD_LEVEL=$(jq -rn --argjson rank "$LEVEL_RANK" --argjson t "$THRESHOLD_RANK" \
    '$rank | to_entries | map(select(.value == $t)) | .[0].key')
  RISK_RANK=$(jq -nr --argjson rank "$LEVEL_RANK" --arg r "$RISK_LEVEL" '$rank[$r] // 99')
  if [[ "$RISK_RANK" -le "$THRESHOLD_RANK" ]]; then
    RESULT="fail"
  else
    RESULT="pass"
  fi
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
  --arg deployment_environment "$DEPLOYMENT_ENVIRONMENT" \
  --arg mitigations "$MITIGATIONS_TEXT" \
  --arg result "$RESULT" \
  --argjson fail_on "$FAIL_ON_JSON" \
  --argjson codeql_open "$CODEQL_OPEN" \
  --argjson dependabot_open "$DEPENDABOT_OPEN" \
  --argjson dependabot_fetched "$DEPENDABOT_FETCHED" \
  --argjson dependabot_duplicates_removed "$DEPENDABOT_DUPES" \
  --argjson codeql_truncated "$CODEQL_TRUNC" \
  --argjson dependabot_truncated "$DEPENDABOT_TRUNC" \
  --argjson kev_catalog_size "$KEV_CATALOG_SIZE" \
  --argjson kev_matched "$KEV_MATCHED" \
  --arg codeql_readable "$CODEQL_READABLE" \
  --arg dependabot_readable "$DEPENDABOT_READABLE" \
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
      app_context: $app_context,
      deployment_environment: $deployment_environment,
      mitigations: $mitigations
    },
    policy: {
      result: $result,
      fail_on: $fail_on
    },
    inputs: {
      codeql_open: $codeql_open,
      dependabot_open: $dependabot_open,
      dependabot_fetched: $dependabot_fetched,
      dependabot_duplicates_removed: $dependabot_duplicates_removed,
      codeql_readable: ($codeql_readable == "ok"),
      dependabot_readable: ($dependabot_readable == "ok"),
      codeql_truncated: $codeql_truncated,
      dependabot_truncated: $dependabot_truncated,
      kev_catalog_size: $kev_catalog_size,
      kev_matched: $kev_matched
    },
    verdict: $verdict,
    alerts: {
      codeql: $codeql,
      dependabot: $dependabot
    }
  }' > "$REPORT_PATH"

echo "Advisory report written to ${REPORT_PATH}"

# --- Write model I/O record (prompt, context, response) ----------------------
# Captures the exact request (system + user prompt with all inputs resolved) and
# the model's response (raw API body + parsed verdict) so the inference itself —
# not just the derived verdict in the advisory report — can be evidenced and,
# optionally, attested. Kept in a separate file from the report so it can be
# signed independently (see the attest-model-io input).
MODEL_IO_PATH="risk-ai-advisor-model-io-${GITHUB_SHA:-local}.json"
# Embed the raw response as JSON when parseable, otherwise as a JSON string.
RAW_RESPONSE_JSON=$(jq -e . <<< "$RAW_RESPONSE" 2>/dev/null || jq -Rs . <<< "$RAW_RESPONSE")
jq -n \
  --arg commit "${GITHUB_SHA:-}" \
  --arg repo "$REPOSITORY" \
  --arg run_url "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-0}" \
  --arg assessed_at "$NOW_ISO" \
  --arg model "$MODEL_USED" \
  --arg system_prompt "$SYSTEM_PROMPT" \
  --arg user_prompt "$USER_PROMPT" \
  --arg app_context "$APP_CONTEXT" \
  --arg deployment_environment "$DEPLOYMENT_ENVIRONMENT" \
  --arg mitigations "$MITIGATIONS_TEXT" \
  --argjson raw "$RAW_RESPONSE_JSON" \
  --argjson verdict "$VERDICT" \
  '{
    audit: {
      commit_sha: $commit,
      repository: $repo,
      run_url: $run_url,
      assessed_at: $assessed_at,
      model: $model
    },
    request: {
      model: $model,
      system_prompt: $system_prompt,
      user_prompt: $user_prompt,
      context: {
        app_context: $app_context,
        deployment_environment: $deployment_environment,
        mitigations: $mitigations
      }
    },
    response: {
      raw: $raw,
      verdict: $verdict
    }
  }' > "$MODEL_IO_PATH"

echo "Model I/O record written to ${MODEL_IO_PATH}"

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
  echo "| Deployment environment | ${DEPLOYMENT_ENVIRONMENT} |"
  echo "| Compensating controls | ${MITIGATIONS_CELL} |"
  echo "| Assessed at | ${NOW_ISO} |"
  echo "| Model | \`${MODEL_USED}\` |"
  codeql_note=""; [[ "$CODEQL_READABLE" == "fail" ]] && codeql_note=" ⚠️ not readable"
  dependabot_note=""; [[ "$DEPENDABOT_READABLE" == "fail" ]] && dependabot_note=" ⚠️ not readable"
  dependabot_dedup_note=""; [[ "$DEPENDABOT_DUPES" -gt 0 ]] && dependabot_dedup_note=" (deduplicated from ${DEPENDABOT_FETCHED}; ${DEPENDABOT_DUPES} duplicate CVE/advisory alert(s) merged)"
  echo "| Open CodeQL alerts | ${CODEQL_OPEN}${codeql_note} |"
  echo "| Open Dependabot alerts | ${DEPENDABOT_OPEN}${dependabot_note}${dependabot_dedup_note} |"
  echo "| 🚨 Known-exploited (CISA KEV) | ${KEV_MATCHED} |"
  echo ""
  if [[ "$DEPENDABOT_READABLE" == "fail" ]]; then
    echo "> ⚠️ **Dependabot alerts could not be read**, so KEV matching had nothing to check (KEV applies to Dependabot CVEs). The default \`GITHUB_TOKEN\` cannot read Dependabot alerts — set the \`dependabot-token\` input to a fine-grained PAT (repo permissions \"Dependabot alerts: read\" + \"Metadata: read\") or a GitHub App token, and ensure Dependabot alerts are enabled for the repository."
    echo ""
  fi
  if [[ "$KEV_MATCHED" -gt 0 ]]; then
    echo "> 🚨 **${KEV_MATCHED} known-exploited CVE(s) (CISA KEV) found in open Dependabot alerts** — these CVEs have confirmed in-the-wild exploitation and should be remediated before release."
    echo ""
    echo "| CVE | Package | Severity | Ransomware | KEV due date |"
    echo "|---|---|---|---|---|"
    jq -r '[ .[] | select(.known_exploited) ] | unique_by(.cve) | .[] | "| \(.cve) | \(.package) | \(.severity) | \(.kev.known_ransomware // "Unknown") | \(.kev.due_date // "n/a") |"' <<< "$DEPENDABOT"
    echo ""
  fi
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
    pass)     echo "**Result: ✅ PASS** — AI risk level \`${RISK_LEVEL}\` is below the \`fail-on\` threshold (\`${THRESHOLD_LEVEL}\` and above)." ;;
    fail)     echo "**Result: ❌ FAIL** — AI risk level \`${RISK_LEVEL}\` is at or above the \`fail-on\` threshold (\`${THRESHOLD_LEVEL}\` and above). Blocking this release." ;;
  esac
  if [[ "$CODEQL_TRUNC" -gt 0 || "$DEPENDABOT_TRUNC" -gt 0 ]]; then
    echo ""
    echo "_Note: ${CODEQL_TRUNC} CodeQL and ${DEPENDABOT_TRUNC} Dependabot alert(s) were omitted from the model prompt to stay within the \`max-alerts\` cap (${MAX_ALERTS}) and the model's input-token limit; counts above are complete._"
    echo ""
    # List the alerts that the model did NOT see so a reviewer can still eyeball
    # them. The alert arrays are pre-sorted KEV-/severity-first, so the omitted
    # set is exactly the tail beyond what was sent ($CODEQL_SENT_N / $DEPENDABOT_SENT_N)
    # — i.e. the lowest-priority findings. Capped to keep the summary bounded.
    OMIT_ROW_CAP=100
    echo "<details><summary>🔎 Omitted alerts not sent to the model (${CODEQL_TRUNC} CodeQL, ${DEPENDABOT_TRUNC} Dependabot)</summary>"
    echo ""
    if [[ "$DEPENDABOT_TRUNC" -gt 0 ]]; then
      echo "**Dependabot — ${DEPENDABOT_TRUNC} omitted** (lowest-priority; sorted after the sent set)"
      echo ""
      echo "| Severity | Package | Advisory | Known-exploited | Fix available | Alert |"
      echo "|---|---|---|---|---|---|"
      jq -r --argjson n "$DEPENDABOT_SENT_N" --argjson cap "$OMIT_ROW_CAP" \
        '.[$n:][0:$cap][] | "| \(.severity) | \(.package) (\(.ecosystem)) | \(.advisory) | \(if .known_exploited then "🚨 yes" else "no" end) | \(if .first_patched_version == "none" then "none" else .first_patched_version end) | [#\(.number)](\(.url)) |"' <<< "$DEPENDABOT"
      if [[ "$DEPENDABOT_TRUNC" -gt "$OMIT_ROW_CAP" ]]; then
        echo ""
        echo "_…and $((DEPENDABOT_TRUNC - OMIT_ROW_CAP)) more Dependabot alert(s) not listed (see the JSON advisory report for the complete set)._"
      fi
      echo ""
    fi
    if [[ "$CODEQL_TRUNC" -gt 0 ]]; then
      echo "**CodeQL — ${CODEQL_TRUNC} omitted** (lowest-priority; sorted after the sent set)"
      echo ""
      echo "| Severity | Rule | File | Alert |"
      echo "|---|---|---|---|"
      jq -r --argjson n "$CODEQL_SENT_N" --argjson cap "$OMIT_ROW_CAP" \
        '.[$n:][0:$cap][] | "| \(.severity) | \(.name // .rule_id) | `\(.file)` | [#\(.number)](\(.url)) |"' <<< "$CODEQL"
      if [[ "$CODEQL_TRUNC" -gt "$OMIT_ROW_CAP" ]]; then
        echo ""
        echo "_…and $((CODEQL_TRUNC - OMIT_ROW_CAP)) more CodeQL alert(s) not listed (see the JSON advisory report for the complete set)._"
      fi
      echo ""
    fi
    echo "</details>"
  fi

  # Model prompt, context, and response — collapsed by default so a reviewer can
  # expand and audit exactly what was sent to and returned by the model. The full
  # raw API body is in the workflow log and the attestable model-I/O record.
  echo "<details><summary>🧾 Model prompt, context and response (click to expand)</summary>"
  echo ""
  echo "**Model:** \`${MODEL_USED}\`"
  echo ""
  echo "**Context sent to the model**"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| App context | ${APP_CONTEXT_CELL} |"
  echo "| Deployment environment | ${DEPLOYMENT_ENVIRONMENT_CELL} |"
  echo "| Compensating controls | ${MITIGATIONS_CELL} |"
  echo ""
  if [[ "$TOTAL_OPEN" -eq 0 ]]; then
    echo "> No model call was made — there were no open CodeQL or Dependabot alerts, so a deterministic \`minimal\` / \`go\` verdict was recorded without querying the model."
    echo ""
  else
    echo "**System prompt**"
    echo ""
    echo '```text'
    echo "$SYSTEM_PROMPT"
    echo '```'
    echo ""
    echo "**User prompt (context + alert data actually sent)**"
    echo ""
    echo '```text'
    echo "$USER_PROMPT"
    echo '```'
    echo ""
  fi
  echo "**Model response (verdict)**"
  echo ""
  echo '```json'
  jq . <<< "$VERDICT"
  echo '```'
  echo "</details>"
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
  echo "kev-matched=${KEV_MATCHED}"
  echo "audited-commit=${GITHUB_SHA:-}"
  echo "report-path=${REPORT_PATH}"
  echo "model-io-path=${MODEL_IO_PATH}"
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
