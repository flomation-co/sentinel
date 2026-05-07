#!/usr/bin/env bash
#
# security-scan.sh — Multi-ecosystem security scanner
#
# Detects Go, JavaScript/TypeScript, Terraform, Docker, and general
# secrets/vulnerabilities in a repository and runs best-practice
# static analysis and dependency audit tools against them.
#
# Produces a structured JSON report at the end for cross-run comparison.
#
# Usage:
#   ./security-scan.sh [OPTIONS]
#
# Options:
#   -d, --dir <path>       Repository root to scan (default: current directory)
#   -o, --output <path>    Output report path (default: ./security-report-<timestamp>.json)
#   -s, --severity <level> Minimum severity: info|low|medium|high|critical (default: low)
#   -k, --skip <tools>     Comma-separated tools to skip (e.g. trivy,gosec)
#   -q, --quiet            Suppress per-tool stdout, only show summary
#   --ci                   Running in CI — auto-detected in GitLab CI
#   --install              Attempt to install missing tools
#   -h, --help             Show this help
#
# Exit codes:
#   0  No findings
#   1  Findings detected (warnings or errors)
#   2  Script/tool error
#

set -euo pipefail

# ─── PATH enrichment ────────────────────────────────────────────────────────
# Ensure go-installed and pip-installed binaries are discoverable

if command -v go &>/dev/null; then
    export PATH="${PATH}:$(go env GOPATH 2>/dev/null)/bin"
fi
# Python user-local bin (macOS / Linux)
export PATH="${PATH}:${HOME}/.local/bin:${HOME}/Library/Python/3.11/bin:${HOME}/Library/Python/3.12/bin:${HOME}/Library/Python/3.13/bin"
# Homebrew common paths (Apple Silicon + Intel)
export PATH="${PATH}:/opt/homebrew/bin:/usr/local/bin"

# ─── Defaults ────────────────────────────────────────────────────────────────

SCAN_DIR="$(pwd)"
OUTPUT_PATH=""
MIN_SEVERITY="low"
SKIP_TOOLS=""
QUIET=false
CI_MODE=false
AUTO_INSTALL=false
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR=""
TOTAL_FINDINGS=0
TOOL_RESULTS=()
TOOLS_RUN=()
TOOLS_SKIPPED=()
TOOLS_MISSING=()
ECOSYSTEMS_DETECTED=()

# Severity ordinal for comparison (function avoids declare -A / set -u issues)
sev_rank() {
    case "${1,,}" in
        info)     echo 0 ;;
        low)      echo 1 ;;
        medium)   echo 2 ;;
        high)     echo 3 ;;
        critical) echo 4 ;;
        *)        echo 0 ;;
    esac
}

# Colours (disabled in CI or non-tty)
if [[ -t 1 ]] && [[ -z "${CI:-}" ]]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' YELLOW='' GREEN='' CYAN='' BOLD='' RESET=''
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

log()      { echo -e "${CYAN}[scan]${RESET} $*"; }
log_ok()   { echo -e "${GREEN}[  ok]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}[warn]${RESET} $*"; }
log_err()  { echo -e "${RED}[ err]${RESET} $*"; }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
}

severity_meets_threshold() {
    local sev="${1,,}"
    local threshold="${MIN_SEVERITY,,}"
    [[ $(sev_rank "$sev") -ge $(sev_rank "$threshold") ]]
}

tool_available() {
    command -v "$1" &>/dev/null
}

should_skip() {
    local tool="$1"
    [[ ",$SKIP_TOOLS," == *",$tool,"* ]]
}

# Portable JSON string escaper (no jq dependency for this part)
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    echo -n "$s"
}

# ─── Parse arguments ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)       SCAN_DIR="$2"; shift 2 ;;
        -o|--output)    OUTPUT_PATH="$2"; shift 2 ;;
        -s|--severity)  MIN_SEVERITY="$2"; shift 2 ;;
        -k|--skip)      SKIP_TOOLS="$2"; shift 2 ;;
        -q|--quiet)     QUIET=true; shift ;;
        --ci)           CI_MODE=true; shift ;;
        --install)      AUTO_INSTALL=true; shift ;;
        -h|--help)      usage ;;
        *)              log_err "Unknown option: $1"; usage ;;
    esac
done

# Auto-detect CI
if [[ -n "${GITLAB_CI:-}" ]] || [[ -n "${CI:-}" ]]; then
    CI_MODE=true
fi

SCAN_DIR="$(cd "$SCAN_DIR" && pwd)"
REPORT_DIR="$(mktemp -d)"

if [[ -z "$OUTPUT_PATH" ]]; then
    OUTPUT_PATH="${SCAN_DIR}/security-report-${TIMESTAMP}.json"
fi

log "${BOLD}Security Scan — $(date -u)${RESET}"
log "Scanning:  ${SCAN_DIR}"
log "Severity:  >= ${MIN_SEVERITY}"
log "Report:    ${OUTPUT_PATH}"
echo ""

# ─── Ecosystem detection ────────────────────────────────────────────────────

detect_ecosystems() {
    log "Detecting project ecosystems..."

    if find "$SCAN_DIR" -maxdepth 4 -name 'go.mod' -o -name '*.go' 2>/dev/null | head -1 | grep -q .; then
        ECOSYSTEMS_DETECTED+=(golang)
        log_ok "Go"
    fi

    if find "$SCAN_DIR" -maxdepth 4 -name 'package.json' 2>/dev/null | head -1 | grep -q .; then
        ECOSYSTEMS_DETECTED+=(javascript)
        log_ok "JavaScript / TypeScript"
    fi

    if find "$SCAN_DIR" -maxdepth 4 -name '*.tf' 2>/dev/null | head -1 | grep -q .; then
        ECOSYSTEMS_DETECTED+=(terraform)
        log_ok "Terraform"
    fi

    if find "$SCAN_DIR" -maxdepth 4 -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' 2>/dev/null | head -1 | grep -q .; then
        ECOSYSTEMS_DETECTED+=(docker)
        log_ok "Docker"
    fi

    if find "$SCAN_DIR" -maxdepth 4 -name '*.py' -o -name 'requirements*.txt' -o -name 'pyproject.toml' 2>/dev/null | head -1 | grep -q .; then
        ECOSYSTEMS_DETECTED+=(python)
        log_ok "Python"
    fi

    # Always run generic scanners
    ECOSYSTEMS_DETECTED+=(generic)

    echo ""
}

# ─── Tool installation helpers ──────────────────────────────────────────────

try_install() {
    local tool="$1"
    if ! $AUTO_INSTALL; then
        TOOLS_MISSING+=("$tool")
        return 1
    fi

    log "Attempting to install ${tool}..."

    local IS_MAC=false
    [[ "$(uname)" == "Darwin" ]] && IS_MAC=true

    # Helper: try pip with correct flags for modern Python
    pip_install() {
        local pkg="$1"
        local PIP_CMD=""
        if command -v pip3 &>/dev/null; then PIP_CMD="pip3"
        elif command -v pip &>/dev/null; then PIP_CMD="pip"
        else return 1; fi

        # Modern Python requires --break-system-packages outside a venv
        $PIP_CMD install --user --break-system-packages "$pkg" 2>/dev/null \
            || $PIP_CMD install --user "$pkg" 2>/dev/null \
            || $PIP_CMD install "$pkg" 2>/dev/null
    }

    # Helper: try brew (macOS)
    brew_install() {
        $IS_MAC && command -v brew &>/dev/null && brew install "$1" 2>/dev/null
    }

    case "$tool" in
        gosec)
            go install github.com/securego/gosec/v2/cmd/gosec@latest 2>/dev/null && return 0
            brew_install gosec && return 0 ;;
        staticcheck)
            go install honnef.co/go/tools/cmd/staticcheck@latest 2>/dev/null && return 0 ;;
        govulncheck)
            go install golang.org/x/vuln/cmd/govulncheck@latest 2>/dev/null && return 0 ;;
        trivy)
            brew_install trivy && return 0
            if [[ "$(uname)" == "Linux" ]]; then
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null && return 0
            fi ;;
        semgrep)
            pip_install semgrep && command -v semgrep &>/dev/null && return 0
            brew_install semgrep && return 0 ;;
        tfsec)
            go install github.com/aquasecurity/tfsec/cmd/tfsec@latest 2>/dev/null && return 0
            brew_install tfsec && return 0 ;;
        checkov)
            pip_install checkov && command -v checkov &>/dev/null && return 0
            brew_install checkov && return 0 ;;
        gitleaks)
            go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null && command -v gitleaks &>/dev/null && return 0
            brew_install gitleaks && return 0 ;;
        bandit)
            pip_install bandit && command -v bandit &>/dev/null && return 0 ;;
        safety)
            pip_install safety && command -v safety &>/dev/null && return 0 ;;
    esac

    TOOLS_MISSING+=("$tool")
    return 1
}

require_tool() {
    local tool="$1"
    if should_skip "$tool"; then
        TOOLS_SKIPPED+=("$tool")
        return 1
    fi
    if ! tool_available "$tool"; then
        if ! try_install "$tool"; then
            log_warn "${tool} not found — skipping (use --install to auto-install)"
            return 1
        fi
        # Refresh bash's command hash after install
        hash -r 2>/dev/null || true
        if ! tool_available "$tool"; then
            log_warn "${tool} installed but not found in PATH — skipping"
            TOOLS_MISSING+=("$tool")
            return 1
        fi
        log_ok "${tool} installed successfully"
    fi
    return 0
}

# ─── Tool runners ───────────────────────────────────────────────────────────
#
# Each run_* function:
#   1. Runs the tool, capturing output to a temp file
#   2. Parses findings into a normalised JSON array
#   3. Appends to TOOL_RESULTS and increments TOTAL_FINDINGS
#

# ── Go: gosec ────────────────────────────────────────────────────────────────

run_gosec() {
    require_tool gosec || return 0
    log "Running gosec..."

    local out="${REPORT_DIR}/gosec.json"
    # gosec exits non-zero when findings exist, which is expected
    gosec -fmt=json -severity=low -confidence=low ./... > "$out" 2>/dev/null || true

    # Parse: gosec JSON has .Issues[]
    local count
    count=$(jq '.Issues | length' "$out" 2>/dev/null || echo 0)

    if [[ "$count" -gt 0 ]]; then
        local findings
        findings=$(jq -c '[.Issues[] | {
            tool: "gosec",
            rule: .rule_id,
            severity: (.severity // "medium" | ascii_downcase),
            confidence: (.confidence // "unknown" | ascii_downcase),
            message: .details,
            file: .file,
            line: (.line | tonumber? // 0),
            code: .code
        }]' "$out" 2>/dev/null || echo "[]")

        # Filter by severity threshold
        local filtered
        filtered=$(echo "$findings" | jq -c --arg min "${MIN_SEVERITY}" '
            def sev_rank: {"info":0,"low":1,"medium":2,"high":3,"critical":4};
            [ .[] | select( (sev_rank[.severity] // 0) >= (sev_rank[$min] // 0) ) ]
        ')
        local fcount
        fcount=$(echo "$filtered" | jq 'length')

        TOOL_RESULTS+=("$filtered")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
        TOOLS_RUN+=(gosec)

        if [[ "$fcount" -gt 0 ]]; then
            log_warn "gosec: ${fcount} finding(s)"
            if ! $QUIET; then
                echo "$filtered" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — \(.message)"'
            fi
        else
            log_ok "gosec: 0 findings (after threshold filter)"
        fi
    else
        TOOLS_RUN+=(gosec)
        log_ok "gosec: clean"
    fi
}

# ── Go: staticcheck ─────────────────────────────────────────────────────────

run_staticcheck() {
    require_tool staticcheck || return 0
    log "Running staticcheck..."

    local out="${REPORT_DIR}/staticcheck.txt"
    staticcheck -f json ./... > "$out" 2>/dev/null || true

    # staticcheck JSON is one object per line (NDJSON)
    # Filter out "compile" diagnostics — these are toolchain/version issues, not code findings
    local findings="[]"
    if [[ -s "$out" ]]; then
        # Check for tool-level errors (e.g. Go version mismatch) and warn
        local compile_errors
        compile_errors=$(jq -sc '[.[] | select(.code == "compile")]' "$out" 2>/dev/null || echo "[]")
        local ce_count
        ce_count=$(echo "$compile_errors" | jq 'length')
        if [[ "$ce_count" -gt 0 ]]; then
            log_warn "staticcheck: ${ce_count} compile diagnostic(s) skipped (check Go/staticcheck version compatibility)"
        fi

        findings=$(jq -sc '[.[] | select(.code != "compile" and .code != "error") | {
            tool: "staticcheck",
            rule: .code,
            severity: (if (.code | startswith("SA")) then "high"
                       elif (.code | startswith("S1")) then "medium"
                       else "low" end),
            confidence: "high",
            message: .message,
            file: .location.file,
            line: .location.line,
            code: ""
        }]' "$out" 2>/dev/null || echo "[]")
    fi

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(staticcheck)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "staticcheck: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — [\(.rule)] \(.message)"'
        fi
    else
        log_ok "staticcheck: clean"
    fi
}

# ── Go: govulncheck ─────────────────────────────────────────────────────────

run_govulncheck() {
    require_tool govulncheck || return 0
    log "Running govulncheck..."

    local out="${REPORT_DIR}/govulncheck.json"
    govulncheck -json ./... > "$out" 2>/dev/null || true

    # govulncheck JSON stream — extract vulnerability findings
    local findings
    findings=$(jq -sc '
        [ .[] | select(.finding != null) | .finding | {
            tool: "govulncheck",
            rule: .osv,
            severity: "high",
            confidence: "high",
            message: ("Vulnerable dependency: " + .osv),
            file: ((.trace[0].module // "") + "@" + (.trace[0].version // "")),
            line: 0,
            code: (.trace[0].function // "")
        }] | unique_by(.rule)
    ' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(govulncheck)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "govulncheck: ${fcount} vulnerability(ies)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file) — \(.message)"'
        fi
    else
        log_ok "govulncheck: clean"
    fi
}

# ── JavaScript: npm audit ────────────────────────────────────────────────────

run_npm_audit() {
    require_tool npm || return 0
    log "Running npm audit..."

    # Find all package.json dirs (skip node_modules)
    local findings="[]"
    local total=0

    while IFS= read -r pkg_dir; do
        local dir
        dir="$(dirname "$pkg_dir")"
        local out="${REPORT_DIR}/npm-audit-$(echo "$dir" | md5sum | cut -c1-8).json"

        # npm audit needs a lockfile; skip if missing
        if [[ ! -f "${dir}/package-lock.json" ]] && [[ ! -f "${dir}/yarn.lock" ]]; then
            continue
        fi

        (cd "$dir" && npm audit --json > "$out" 2>/dev/null) || true

        if [[ -s "$out" ]]; then
            local parsed
            parsed=$(jq -c --arg dir "$dir" '
                [(.vulnerabilities // {}) | to_entries[] | .value | {
                    tool: "npm-audit",
                    rule: .name,
                    severity: (.severity // "medium" | ascii_downcase),
                    confidence: "high",
                    message: ("Vulnerable package: " + .name + " — " + (.title // .via[0].title // "see advisory")),
                    file: ($dir + "/package.json"),
                    line: 0,
                    code: (.range // "")
                }]
            ' "$out" 2>/dev/null || echo "[]")

            local cnt
            cnt=$(echo "$parsed" | jq 'length')
            total=$((total + cnt))
            findings=$(echo "$findings" "$parsed" | jq -sc '.[0] + .[1]')
        fi
    done < <(find "$SCAN_DIR" -maxdepth 4 -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null)

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + total))
    TOOLS_RUN+=(npm-audit)

    if [[ "$total" -gt 0 ]]; then
        log_warn "npm audit: ${total} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file) — \(.message)"'
        fi
    else
        log_ok "npm audit: clean"
    fi
}

# ── Terraform: tfsec ─────────────────────────────────────────────────────────

run_tfsec() {
    require_tool tfsec || return 0
    log "Running tfsec..."

    local out="${REPORT_DIR}/tfsec.json"
    tfsec "$SCAN_DIR" --format=json --include-passed=false --soft-fail > "$out" 2>/dev/null || true

    local findings
    findings=$(jq -c '[(.results // [])[] | {
        tool: "tfsec",
        rule: .rule_id,
        severity: (.severity // "medium" | ascii_downcase),
        confidence: "high",
        message: .description,
        file: .location.filename,
        line: (.location.start_line // 0),
        code: (.resource // "")
    }]' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(tfsec)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "tfsec: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — [\(.rule)] \(.message)"'
        fi
    else
        log_ok "tfsec: clean"
    fi
}

# ── Terraform: checkov ───────────────────────────────────────────────────────

run_checkov() {
    require_tool checkov || return 0
    log "Running checkov..."

    local out="${REPORT_DIR}/checkov.json"
    checkov -d "$SCAN_DIR" --quiet --compact --output=json > "$out" 2>/dev/null || true

    local findings
    findings=$(jq -c '
        (if type == "array" then . else [.] end) |
        [.[] | (.results.failed_checks // [])[] | {
            tool: "checkov",
            rule: .check_id,
            severity: (
                if .severity then (.severity | ascii_downcase)
                elif (.check_id | startswith("CKV_AWS")) then "medium"
                else "low" end
            ),
            confidence: "high",
            message: .check_id + ": " + (.name // "unnamed check"),
            file: .file_path,
            line: (.file_line_range[0] // 0),
            code: (.resource // "")
        }]
    ' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(checkov)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "checkov: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — \(.message)"' | head -30
            local remaining=$((fcount - 30))
            [[ $remaining -gt 0 ]] && echo "  ... and ${remaining} more"
        fi
    else
        log_ok "checkov: clean"
    fi
}

# ── Docker / General: trivy ─────────────────────────────────────────────────

run_trivy() {
    require_tool trivy || return 0
    log "Running trivy (filesystem scan)..."

    local out="${REPORT_DIR}/trivy.json"
    trivy fs --format json --severity LOW,MEDIUM,HIGH,CRITICAL \
        --scanners vuln,misconfig,secret \
        "$SCAN_DIR" > "$out" 2>/dev/null || true

    local findings
    findings=$(jq -c '
        [(.Results // [])[] | . as $result |
            ((.Vulnerabilities // [])[] | {
                tool: "trivy",
                rule: .VulnerabilityID,
                severity: (.Severity // "medium" | ascii_downcase),
                confidence: "high",
                message: (.Title // .VulnerabilityID) + " in " + (.PkgName // "unknown") + "@" + (.InstalledVersion // "?"),
                file: $result.Target,
                line: 0,
                code: (.FixedVersion // "no fix available")
            }),
            ((.Misconfigurations // [])[] | {
                tool: "trivy",
                rule: .ID,
                severity: (.Severity // "medium" | ascii_downcase),
                confidence: "high",
                message: .Title,
                file: $result.Target,
                line: 0,
                code: (.Resolution // "")
            }),
            ((.Secrets // [])[] | {
                tool: "trivy",
                rule: .RuleID,
                severity: "critical",
                confidence: "high",
                message: "Secret detected: " + (.Title // .RuleID),
                file: $result.Target,
                line: (.StartLine // 0),
                code: ""
            })
        ]
    ' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(trivy)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "trivy: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file) — \(.message)"' | head -30
            local remaining=$((fcount - 30))
            [[ $remaining -gt 0 ]] && echo "  ... and ${remaining} more"
        fi
    else
        log_ok "trivy: clean"
    fi
}

# ── Generic: semgrep ─────────────────────────────────────────────────────────

run_semgrep() {
    require_tool semgrep || return 0
    log "Running semgrep..."

    local out="${REPORT_DIR}/semgrep.json"

    # Use auto config which pulls community rulesets matched to detected languages
    semgrep scan --config=auto --json --quiet "$SCAN_DIR" > "$out" 2>/dev/null || true

    local findings
    findings=$(jq -c '[(.results // [])[] | {
        tool: "semgrep",
        rule: .check_id,
        severity: (
            if .extra.severity == "ERROR" then "high"
            elif .extra.severity == "WARNING" then "medium"
            else "low" end
        ),
        confidence: (.extra.metadata.confidence // "medium" | ascii_downcase),
        message: .extra.message,
        file: .path,
        line: .start.line,
        code: (.extra.lines // "")
    }]' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(semgrep)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "semgrep: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — \(.message)"' | head -30
            local remaining=$((fcount - 30))
            [[ $remaining -gt 0 ]] && echo "  ... and ${remaining} more"
        fi
    else
        log_ok "semgrep: clean"
    fi
}

# ── Generic: gitleaks (secrets) ──────────────────────────────────────────────

run_gitleaks() {
    require_tool gitleaks || return 0
    log "Running gitleaks..."

    local out="${REPORT_DIR}/gitleaks.json"
    gitleaks detect --source="$SCAN_DIR" --report-format=json --report-path="$out" --no-banner 2>/dev/null || true

    if [[ -s "$out" ]]; then
        local findings
        findings=$(jq -c '[.[] | {
            tool: "gitleaks",
            rule: .RuleID,
            severity: "critical",
            confidence: "high",
            message: "Secret detected: " + (.Description // .RuleID),
            file: .File,
            line: (.StartLine // 0),
            code: ""
        }]' "$out" 2>/dev/null || echo "[]")

        local fcount
        fcount=$(echo "$findings" | jq 'length')

        TOOL_RESULTS+=("$findings")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
        TOOLS_RUN+=(gitleaks)

        if [[ "$fcount" -gt 0 ]]; then
            log_warn "gitleaks: ${fcount} secret(s) detected"
            if ! $QUIET; then
                echo "$findings" | jq -r '.[] | "  CRITICAL \(.file):\(.line) — \(.message)"'
            fi
        else
            log_ok "gitleaks: clean"
        fi
    else
        TOOLS_RUN+=(gitleaks)
        log_ok "gitleaks: clean"
    fi
}

# ── Python: bandit ───────────────────────────────────────────────────────────

run_bandit() {
    require_tool bandit || return 0
    log "Running bandit..."

    local out="${REPORT_DIR}/bandit.json"
    bandit -r "$SCAN_DIR" -f json -ll > "$out" 2>/dev/null || true

    local findings
    findings=$(jq -c '[(.results // [])[] | {
        tool: "bandit",
        rule: .test_id,
        severity: (.issue_severity // "medium" | ascii_downcase),
        confidence: (.issue_confidence // "medium" | ascii_downcase),
        message: .issue_text,
        file: .filename,
        line: (.line_number // 0),
        code: (.test_name // "")
    }]' "$out" 2>/dev/null || echo "[]")

    local fcount
    fcount=$(echo "$findings" | jq 'length')

    TOOL_RESULTS+=("$findings")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + fcount))
    TOOLS_RUN+=(bandit)

    if [[ "$fcount" -gt 0 ]]; then
        log_warn "bandit: ${fcount} finding(s)"
        if ! $QUIET; then
            echo "$findings" | jq -r '.[] | "  \(.severity | ascii_upcase) \(.file):\(.line) — \(.message)"'
        fi
    else
        log_ok "bandit: clean"
    fi
}

# ─── Run scanners per ecosystem ─────────────────────────────────────────────

run_scans() {
    cd "$SCAN_DIR"

    for eco in "${ECOSYSTEMS_DETECTED[@]}"; do
        case "$eco" in
            golang)
                echo ""
                log "${BOLD}── Go ──${RESET}"
                run_gosec
                run_staticcheck
                run_govulncheck
                ;;
            javascript)
                echo ""
                log "${BOLD}── JavaScript / TypeScript ──${RESET}"
                run_npm_audit
                ;;
            terraform)
                echo ""
                log "${BOLD}── Terraform ──${RESET}"
                run_tfsec
                run_checkov
                ;;
            python)
                echo ""
                log "${BOLD}── Python ──${RESET}"
                run_bandit
                ;;
            docker|generic)
                ;; # handled below
        esac
    done

    echo ""
    log "${BOLD}── General / Cross-language ──${RESET}"
    run_trivy
    run_semgrep
    run_gitleaks
}

# ─── Report generation ──────────────────────────────────────────────────────

generate_report() {
    log ""
    log "${BOLD}Generating report...${RESET}"

    # Merge all findings arrays
    local all_findings="[]"
    for result in "${TOOL_RESULTS[@]}"; do
        all_findings=$(echo "$all_findings" "$result" | jq -sc '.[0] + .[1]')
    done

    # Build severity summary
    local summary
    summary=$(echo "$all_findings" | jq -c '{
        critical: [.[] | select(.severity == "critical")] | length,
        high:     [.[] | select(.severity == "high")] | length,
        medium:   [.[] | select(.severity == "medium")] | length,
        low:      [.[] | select(.severity == "low")] | length,
        info:     [.[] | select(.severity == "info")] | length
    }')

    # Build per-tool summary
    local tool_summary
    tool_summary=$(echo "$all_findings" | jq -c '
        group_by(.tool) | map({
            tool: .[0].tool,
            count: length,
            severities: (group_by(.severity) | map({key: .[0].severity, value: length}) | from_entries)
        })
    ')

    # Git metadata (if available)
    local git_branch="" git_commit="" git_author=""
    if tool_available git && git -C "$SCAN_DIR" rev-parse --git-dir &>/dev/null; then
        git_branch="$(git -C "$SCAN_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
        git_commit="$(git -C "$SCAN_DIR" rev-parse --short HEAD 2>/dev/null || echo "")"
        git_author="$(git -C "$SCAN_DIR" log -1 --format='%an <%ae>' 2>/dev/null || echo "")"
    fi

    # CI metadata
    local ci_pipeline="" ci_job=""
    if $CI_MODE; then
        ci_pipeline="${CI_PIPELINE_ID:-${CI_PIPELINE_IID:-}}"
        ci_job="${CI_JOB_ID:-}"
    fi

    # Assemble final report
    jq -n \
        --arg ts "$TIMESTAMP" \
        --arg dir "$SCAN_DIR" \
        --arg branch "$git_branch" \
        --arg commit "$git_commit" \
        --arg author "$git_author" \
        --arg ci_pipeline "$ci_pipeline" \
        --arg ci_job "$ci_job" \
        --arg min_sev "$MIN_SEVERITY" \
        --argjson total "$TOTAL_FINDINGS" \
        --argjson summary "$summary" \
        --argjson tool_summary "$tool_summary" \
        --argjson findings "$all_findings" \
        '{
            metadata: {
                timestamp: $ts,
                scan_directory: $dir,
                git: {
                    branch: $branch,
                    commit: $commit,
                    author: $author
                },
                ci: {
                    pipeline_id: $ci_pipeline,
                    job_id: $ci_job
                },
                minimum_severity: $min_sev,
                tools_run: ($tool_summary | map(.tool)),
                ecosystems: []
            },
            summary: ($summary + {total: $total}),
            by_tool: $tool_summary,
            findings: $findings
        }' \
        --argjson ecos "$(printf '%s\n' "${ECOSYSTEMS_DETECTED[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')" \
        '.metadata.ecosystems = $ecos' \
    > "$OUTPUT_PATH"

    log_ok "Report written to: ${OUTPUT_PATH}"
}

# ─── Summary and exit ───────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [[ "$TOTAL_FINDINGS" -eq 0 ]]; then
        log_ok "${BOLD}All clear — no findings detected${RESET}"
    else
        log_err "${BOLD}${TOTAL_FINDINGS} total finding(s) detected${RESET}"
        echo ""
        jq -r '.summary | "  Critical: \(.critical)  High: \(.high)  Medium: \(.medium)  Low: \(.low)  Info: \(.info)"' "$OUTPUT_PATH"
    fi

    echo ""
    echo "  Tools run:     ${TOOLS_RUN[*]:-none}"
    [[ ${#TOOLS_SKIPPED[@]} -gt 0 ]] && echo "  Tools skipped: ${TOOLS_SKIPPED[*]}"
    [[ ${#TOOLS_MISSING[@]} -gt 0 ]] && echo "  Tools missing: ${TOOLS_MISSING[*]}"
    echo "  Ecosystems:    ${ECOSYSTEMS_DETECTED[*]}"
    echo "  Report:        ${OUTPUT_PATH}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ─── Main ───────────────────────────────────────────────────────────────────

main() {
    # Require jq — everything else is optional
    if ! tool_available jq; then
        log_err "jq is required but not found. Install it first."
        exit 2
    fi

    detect_ecosystems
    run_scans
    generate_report
    print_summary

    # Clean up
    rm -rf "$REPORT_DIR"

    # Exit non-zero if ANY findings at or above threshold
    if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main