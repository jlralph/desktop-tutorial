#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# CISA KEV catalog helper
# Builds a compact CVE -> KEV-record map from the CISA Known Exploited
# Vulnerabilities (KEV) catalog and prints the path of the map file to stdout.
#
# The KEV catalog lists CVEs with evidence of active, in-the-wild exploitation.
# A Dependabot alert whose CVE appears here is a major risk amplifier (proven
# exploitation, often with a federal remediation due date), so the caller
# annotates matches and tells the model to weigh them heavily. A network/parse
# failure degrades to an empty catalog ({}) so the advisor still runs on the
# rest of the signal.
#
# Usage:
#   KEV_FILE=$(KEV_CACHE_DIR=/some/dir kev_catalog.sh)
#
# When KEV_CACHE_DIR is set (persisted across runs by actions/cache), the map is
# kept there so repeat runs skip the download; otherwise a temp file is used and
# the caller is responsible for removing it. Only the map file path is written to
# stdout; all human-readable logging goes to stderr.
# ---------------------------------------------------------------------------

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Build the compact CVE -> KEV-record map at $1 (a file path). Reuses a valid
# cached copy when present, otherwise downloads and writes it. Degrades to an
# empty map ({}) on any failure so the advisor still runs.
build_kev_map() {
  local out="$1" raw tmp
  # Validate a cached map against the shape we produced: an object whose keys are
  # CVE ids and whose values carry at least a matching .cve field. This defends
  # against a poisoned cache (an attacker with actions:write on the branch could
  # otherwise plant any JSON object here to bias the AI verdict).
  if [[ -s "$out" ]] && jq -e '
        (type == "object") and
        (to_entries | all(
             (.key   | test("^CVE-[0-9]{4}-[0-9]+$"))
             and (.value | type == "object")
             and ((.value.cve // "") == .key)
        ))
      ' "$out" >/dev/null 2>&1; then
    echo "Reusing cached CISA KEV catalog (${out})." >&2
    return 0
  fi
  # Write via a temp file next to the target and atomic-mv so a partial or invalid
  # write can never leave a poisoned map behind for the next run to reuse.
  tmp=$(mktemp "${out}.XXXXXX")
  if raw=$(curl -sSf --max-time 30 "$KEV_URL" 2>/dev/null) \
     && jq -e '.vulnerabilities | type == "array"' <<< "$raw" >/dev/null 2>&1; then
    jq -c '[ .vulnerabilities[]
             | select(.cveID | type == "string" and test("^CVE-[0-9]{4}-[0-9]+$"))
             | {
                 key: .cveID,
                 value: {
                   cve: .cveID,
                   name: .vulnerabilityName,
                   date_added: .dateAdded,
                   due_date: .dueDate,
                   known_ransomware: .knownRansomwareCampaignUse,
                   required_action: .requiredAction
                 }
               } ] | from_entries'  <<< "$raw" > "$tmp"
  else
    echo "::warning::Could not fetch/parse the CISA KEV catalog; proceeding without known-exploited enrichment." >&2
    echo "{}" > "$tmp"
  fi
  mv -f "$tmp" "$out"
}

# When the action supplies a cache dir (persisted across runs by actions/cache),
# keep the map there so repeat runs skip the download; otherwise use a temp file.
# The map is large (1600+ entries) and is fed to jq via --slurpfile rather than
# --argjson by the caller: that big a value in argv overflows ARG_MAX ("Argument
# list too long"). Here-strings (<<<) go to stdin, so reading its length is
# unaffected.
if [[ -n "${KEV_CACHE_DIR:-}" ]]; then
  mkdir -p "$KEV_CACHE_DIR"
  KEV_FILE="${KEV_CACHE_DIR}/kev-map.json"
else
  KEV_FILE=$(mktemp)
fi
build_kev_map "$KEV_FILE"

echo "$KEV_FILE"
