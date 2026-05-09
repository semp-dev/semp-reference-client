#!/usr/bin/env bash
# Federation smoke test for two SEMP servers.
#
# Builds the reference client, registers alice and bob on each domain,
# then sends and fetches messages in all four directions:
#
#   1. same-domain on server A   (alice@A -> bob@A)
#   2. same-domain on server B   (alice@B -> bob@B)
#   3. cross-domain A -> B       (alice@A -> bob@B)
#   4. cross-domain B -> A       (alice@B -> bob@A)
#
# Each test sends a uniquely-subjected message and asserts the
# recipient's `fetch` output contains it.
#
# Usage:
#
#   ALICE_PASSWORD=... BOB_PASSWORD=... ./scripts/test-federation.sh
#
# Optional overrides:
#
#   IMPL              implementation to drive        (default: go; values: go|ts)
#   DOMAIN_A          first domain                   (default: schlepping.icu)
#   HOST_A            first domain's server hostname (default: semp.schlepping.icu)
#   DOMAIN_B          second domain                  (default: semp.dev)
#   HOST_B            second domain's server hostname(default: semp.semp.dev)
#   SUITE             crypto suite                   (default: client default)
#   FEDERATION_DELAY  seconds to wait after send     (default: 2)
#   KEEP_WORK_DIR=1   retain WORK_DIR on success too (failures always retain)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration

DOMAIN_A="${DOMAIN_A:-schlepping.icu}"
HOST_A="${HOST_A:-semp.schlepping.icu}"
DOMAIN_B="${DOMAIN_B:-semp.dev}"
HOST_B="${HOST_B:-semp.semp.dev}"
ALICE_PASSWORD="${ALICE_PASSWORD:?ALICE_PASSWORD must be set}"
BOB_PASSWORD="${BOB_PASSWORD:?BOB_PASSWORD must be set}"
SUITE="${SUITE:-}"
FEDERATION_DELAY="${FEDERATION_DELAY:-2}"

IMPL="${IMPL:-go}"
CLIENT_REPO="${CLIENT_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t semp-fed.XXXXXX)}"
case "${IMPL}" in
    go|ts) ;;
    *) printf 'ERROR: IMPL must be go or ts (got %s)\n' "${IMPL}" >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Helpers

log()  { printf '\033[1;34m>>> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
ko()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }
err()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

FAILED=0

cleanup() {
    if [[ "${FAILED}" -gt 0 || -n "${KEEP_WORK_DIR:-}" ]]; then
        printf '\nwork dir retained: %s\n' "${WORK_DIR}"
    else
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build the client

# CLIENT_BIN_CMD is a bash array so we can prefix `node` to the TS impl.
declare -a CLIENT_BIN_CMD
case "${IMPL}" in
    go)
        log "building semp-client (go) from ${CLIENT_REPO}/impl/go"
        BIN="${WORK_DIR}/semp-client"
        ( cd "${CLIENT_REPO}/impl/go" && go build -o "${BIN}" ./cmd/semp-client/ )
        [[ -x "${BIN}" ]] || err "build did not produce ${BIN}"
        CLIENT_BIN_CMD=("${BIN}")
        ;;
    ts)
        log "building semp-client (ts) from ${CLIENT_REPO}/impl/ts"
        ( cd "${CLIENT_REPO}/impl/ts" && npm install --silent && npm run build --silent )
        BUNDLE="${CLIENT_REPO}/impl/ts/dist/cli.js"
        [[ -f "${BUNDLE}" ]] || err "build did not produce ${BUNDLE}"
        CLIENT_BIN_CMD=("node" "${BUNDLE}")
        ;;
esac

# ---------------------------------------------------------------------------
# 2. Write configs

write_config() {
    local user="$1" domain="$2" host="$3"
    local cfg="${WORK_DIR}/${user}-${domain}.toml"
    local db="${WORK_DIR}/${user}-${domain}.db"
    local suite_line=""
    [[ -n "${SUITE}" ]] && suite_line="suite = \"${SUITE}\""
    cat > "${cfg}" <<EOF
identity = "${user}@${domain}"
domain   = "${domain}"
server   = "wss://${host}/v1/ws"
${suite_line}

[database]
path = "${db}"

[tls]
insecure = false
EOF
}

write_config alice "${DOMAIN_A}" "${HOST_A}"
write_config bob   "${DOMAIN_A}" "${HOST_A}"
write_config alice "${DOMAIN_B}" "${HOST_B}"
write_config bob   "${DOMAIN_B}" "${HOST_B}"

# ---------------------------------------------------------------------------
# 3. Register all four

register() {
    local user="$1" domain="$2" pw="$3"
    local cfg="${WORK_DIR}/${user}-${domain}.toml"
    local out="${WORK_DIR}/${user}-${domain}-register.log"
    log "registering ${user}@${domain}"
    if ! "${CLIENT_BIN_CMD[@]}" -config "${cfg}" register -password "${pw}" >"${out}" 2>&1; then
        cat "${out}"
        err "register failed for ${user}@${domain}"
    fi
}

register alice "${DOMAIN_A}" "${ALICE_PASSWORD}"
register bob   "${DOMAIN_A}" "${BOB_PASSWORD}"
register alice "${DOMAIN_B}" "${ALICE_PASSWORD}"
register bob   "${DOMAIN_B}" "${BOB_PASSWORD}"

# ---------------------------------------------------------------------------
# 4. Test cases

TIMESTAMP="$(date +%s)"

run_case() {
    local label="$1"
    local sender_user="$2" sender_domain="$3"
    local recipient_user="$4" recipient_domain="$5"

    local sender_cfg="${WORK_DIR}/${sender_user}-${sender_domain}.toml"
    local recipient_cfg="${WORK_DIR}/${recipient_user}-${recipient_domain}.toml"
    local sender_addr="${sender_user}@${sender_domain}"
    local recipient_addr="${recipient_user}@${recipient_domain}"
    local subject="fed-test-${TIMESTAMP}-${label}"
    local body="federation smoke test ${label} (ts=${TIMESTAMP})"

    log "[${label}] ${sender_addr} -> ${recipient_addr}"

    local send_log="${WORK_DIR}/${label}-send.log"
    if ! "${CLIENT_BIN_CMD[@]}" -config "${sender_cfg}" send \
            -to "${recipient_addr}" \
            -subject "${subject}" \
            -body "${body}" >"${send_log}" 2>&1; then
        ko "${label}: send command exited non-zero"
        return
    fi

    if ! grep -q "${recipient_addr}: delivered" "${send_log}"; then
        ko "${label}: send output did not show 'delivered' for ${recipient_addr}"
        return
    fi

    sleep "${FEDERATION_DELAY}"

    local fetch_log="${WORK_DIR}/${label}-fetch.log"
    if ! "${CLIENT_BIN_CMD[@]}" -config "${recipient_cfg}" fetch >"${fetch_log}" 2>&1; then
        ko "${label}: fetch command exited non-zero"
        return
    fi

    if grep -q "Subject: ${subject}" "${fetch_log}"; then
        ok "${label}"
    else
        ko "${label}: subject '${subject}' not found in fetch output"
    fi
}

run_case "same-A" alice "${DOMAIN_A}" bob "${DOMAIN_A}"
run_case "same-B" alice "${DOMAIN_B}" bob "${DOMAIN_B}"
run_case "x-A-B"  alice "${DOMAIN_A}" bob "${DOMAIN_B}"
run_case "x-B-A"  alice "${DOMAIN_B}" bob "${DOMAIN_A}"

# ---------------------------------------------------------------------------
# 5. Summary

echo
if [[ "${FAILED}" -eq 0 ]]; then
    log "all 4 tests passed"
    exit 0
fi

log "${FAILED} test(s) failed"
exit 1
