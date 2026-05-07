#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Demo wrapper around tools/traffic_generator/run.sh. Drives four canned
# traffic scenarios (legitimate, spoofed, mixed, duplicates) from a
# single command so a live walkthrough doesn't have to remember every
# flag, and tears the children down cleanly when you're done.
#
# Doesn't touch openpenny and doesn't reimplement anything from
# tools/traffic_generator/ -- it only shells out to run.sh, which
# already knows about sudo, the venv, and the Python scripts.
#
# Modes:
#
#   legitimate  Real TCP client against the receiver. Full handshake +
#               steady payload + clean FIN. openpenny should observe
#               closed-loop behaviour (CLOSED_LOOP verdict).
#
#   spoofed     Scapy-injected packets with a forged source IP. The
#               receiver has no return path so nothing ever ACKs, so
#               openpenny's closed-loop check fails.
#
#   mixed       legitimate AND spoofed at the same time, on the same
#               wire and toward the same destination. openpenny should
#               still surface the closed-loop verdict for the legit
#               flow while flagging the rest.
#
#   duplicates  Spoofed flow with a high duplicate probability.
#               Hammers identical SEQ/ACK pairs at openpenny so the
#               aggregate duplicate-fraction threshold trips.
#
#   stop        Terminate every background generator the demo started.
#               Idempotent.
#
#   dry-run     Print the commands that would run, in order, without
#               actually running anything. Optionally takes a mode name
#               to limit the dump to one scenario.
#
# Usage:
#   ./demo_traffic.sh legitimate
#   ./demo_traffic.sh spoofed
#   ./demo_traffic.sh mixed
#   ./demo_traffic.sh duplicates
#   ./demo_traffic.sh dry-run [legitimate|spoofed|mixed|duplicates]
#   ./demo_traffic.sh stop
#
# All knobs in the CONFIG block below can be overridden via env vars,
# e.g.   DURATION_SECONDS=60 PACKET_RATE=200 ./demo_traffic.sh mixed
#
# The defaults intentionally use the RFC 5737 documentation prefixes
# (198.51.100.0/24, TEST-NET-2) so an unconfigured run can't aim
# spoofed traffic at production by accident.

set -euo pipefail

# -----------------------------------------------------------------------------
# CONFIG -- override any of these from the environment.
# -----------------------------------------------------------------------------

# Where the legitimate TCP client connects. The receiver host runs server.py
# (or whatever listener you have) on this host:port.
LEGIT_SRC_HOST="${LEGIT_SRC_HOST:-$(hostname)}"   # informational; appears in log lines
LEGIT_DST_HOST="${LEGIT_DST_HOST:-198.51.100.20}"
LEGIT_DST_PORT="${LEGIT_DST_PORT:-9000}"
LEGIT_INTERVAL_SECS="${LEGIT_INTERVAL_SECS:-1.0}" # seconds between client.py sends

# Spoofed-flow knobs. These map onto spoofed_client.py via run.sh spoof.
SPOOFED_IFACE="${SPOOFED_IFACE:-ens5f0np0}"
SPOOFED_SRC_IP="${SPOOFED_SRC_IP:-198.51.100.10}"
SPOOFED_DST_IP="${SPOOFED_DST_IP:-198.51.100.20}"
SPOOFED_DST_PORT="${SPOOFED_DST_PORT:-9000}"
SPOOFED_FLOWS="${SPOOFED_FLOWS:-1}"

# Wall-clock cap for any one scenario. The orchestrator runs each
# generator under `timeout`, so this is the only knob you need to bound
# a demo segment cleanly.
DURATION_SECONDS="${DURATION_SECONDS:-30}"

# Spoofed flow pacing. PACKET_RATE is in packets per second; we convert
# it to spoofed_client.py's --interval below.
PACKET_RATE="${PACKET_RATE:-50}"

# Per-packet duplicate probability for `duplicates` mode. Range [0.0, 1.0].
# spoofed_client.py exposes this as --duplication-prob.
DUPLICATE_RATE="${DUPLICATE_RATE:-0.5}"

# How long mixed mode waits between starting legit and starting spoofed,
# so the legit flow is established before spoofed background appears.
MIXED_STAGGER_SECS="${MIXED_STAGGER_SECS:-3}"

# -----------------------------------------------------------------------------
# Internal state
# -----------------------------------------------------------------------------

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
TG_DIR="${REPO_ROOT}/tools/traffic_generator"
RUN_SH="${TG_DIR}/run.sh"

PID_FILE="${PID_FILE:-/tmp/openpenny-demo-traffic.pids}"
LOG_FILE="${LOG_FILE:-/tmp/openpenny-demo-traffic.log}"

DRY_RUN="${DRY_RUN:-0}"

# ANSI prefixes for the demo prompts. Stripped automatically when the
# shell isn't a TTY (so logs and tee'd output stay clean).
if [[ -t 1 ]]; then
    C_SETUP="\033[36m"   # cyan
    C_LEGIT="\033[32m"   # green
    C_SPOOF="\033[33m"   # yellow
    C_MIX="\033[35m"     # magenta
    C_DUP="\033[31m"     # red
    C_CLEAN="\033[34m"   # blue
    C_RST="\033[0m"
else
    C_SETUP=""; C_LEGIT=""; C_SPOOF=""; C_MIX=""; C_DUP=""; C_CLEAN=""; C_RST=""
fi

say() {
    # say <prefix-color> <prefix-tag> <message...>
    local color="$1" tag="$2"; shift 2
    printf "${color}[%s]${C_RST} %s\n" "${tag}" "$*"
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

require() {
    # require <command> <human-name>
    local cmd="$1" name="$2"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        say "${C_SETUP}" "setup" "missing tool: ${name} (looked for '${cmd}'). Install it and retry."
        exit 127
    fi
}

ensure_environment() {
    require timeout "GNU coreutils 'timeout'"
    require python3 "Python 3"
    if [[ ! -x "${RUN_SH}" ]]; then
        say "${C_SETUP}" "setup" "tools/traffic_generator/run.sh not found or not executable at ${RUN_SH}"
        exit 1
    fi
    # run.sh handles its own venv; nudge once if it's missing so the
    # first invocation doesn't trigger a surprise install.
    if [[ ! -x "${TG_DIR}/.venv/bin/python" ]]; then
        say "${C_SETUP}" "setup" "first run: scapy venv will be created by run.sh install"
        if [[ "${DRY_RUN}" != "1" ]]; then
            "${RUN_SH}" install
        fi
    fi
}

# Convert PACKET_RATE (pps) to the per-packet --interval that
# spoofed_client.py expects. Falls back to 0 (blast) on bad input.
spoof_interval_from_rate() {
    local rate="${1}"
    awk -v r="${rate}" 'BEGIN { if (r > 0) printf "%.6f", 1.0 / r; else printf "0.0"; }'
}

# Roughly how many packets-per-flow give us DURATION_SECONDS at the
# configured rate. spoofed_client.py exits when each flow has sent its
# count; we also wrap it in `timeout` as a hard cap so this is a
# soft guideline rather than a strict deadline.
spoof_count_for_duration() {
    local duration="${1}" rate="${2}"
    awk -v d="${duration}" -v r="${rate}" \
        'BEGIN { c = d * r; if (c < 1) c = 1; printf "%d", c; }'
}

record_pid() {
    local pid="$1"
    mkdir -p "$(dirname "${PID_FILE}")"
    echo "${pid}" >> "${PID_FILE}"
}

# Run a command in the background under `timeout`, log its stdout/stderr,
# and remember its PID for later cleanup. Honours DRY_RUN.
launch_bg() {
    # launch_bg <log-tag> <duration> <cmd...>
    local tag="$1" duration="$2"; shift 2
    if [[ "${DRY_RUN}" == "1" ]]; then
        printf "[dry-run %s]  timeout %ss %s\n" "${tag}" "${duration}" "$*"
        return 0
    fi
    # Use stdbuf so the demo screen stays responsive instead of buffering.
    ( stdbuf -oL -eL timeout "${duration}s" "$@" 2>&1 \
        | sed -u "s/^/[${tag}] /" \
        | tee -a "${LOG_FILE}" ) &
    local pid=$!
    record_pid "${pid}"
}

# Foreground variant for single-mode runs that should block until done.
launch_fg() {
    # launch_fg <log-tag> <duration> <cmd...>
    local tag="$1" duration="$2"; shift 2
    if [[ "${DRY_RUN}" == "1" ]]; then
        printf "[dry-run %s]  timeout %ss %s\n" "${tag}" "${duration}" "$*"
        return 0
    fi
    stdbuf -oL -eL timeout "${duration}s" "$@" 2>&1 \
        | sed -u "s/^/[${tag}] /" \
        | tee -a "${LOG_FILE}"
}

cleanup() {
    if [[ ! -f "${PID_FILE}" ]]; then
        return 0
    fi
    say "${C_CLEAN}" "cleanup" "stopping background generators"
    while read -r pid; do
        [[ -z "${pid}" ]] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
        fi
    done < "${PID_FILE}"
    # Give them a moment, then force.
    sleep 1
    while read -r pid; do
        [[ -z "${pid}" ]] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            kill -9 "${pid}" 2>/dev/null || true
        fi
    done < "${PID_FILE}"
    rm -f "${PID_FILE}"
}

# Trap so Ctrl-C during any mode tears down children before exiting.
on_signal() {
    echo
    say "${C_CLEAN}" "cleanup" "interrupted, tearing down"
    cleanup
    exit 130
}
trap on_signal INT TERM

# -----------------------------------------------------------------------------
# Mode implementations
# -----------------------------------------------------------------------------

mode_legitimate() {
    # Real SYN, real ACKs from the receiver, payload, clean FIN.
    # openpenny should reach a CLOSED_LOOP verdict on this flow.
    say "${C_LEGIT}" "legitimate" "starting TCP traffic"
    say "${C_LEGIT}" "legitimate" "src=${LEGIT_SRC_HOST} dst=${LEGIT_DST_HOST}:${LEGIT_DST_PORT} interval=${LEGIT_INTERVAL_SECS}s duration=${DURATION_SECONDS}s"
    launch_fg "legitimate" "${DURATION_SECONDS}" \
        "${RUN_SH}" client "${LEGIT_DST_HOST}" "${LEGIT_DST_PORT}" \
            --interval "${LEGIT_INTERVAL_SECS}"
    say "${C_LEGIT}" "legitimate" "traffic running"
    say "${C_LEGIT}" "legitimate" "done"
}

# Internal: spoofed launcher shared by spoofed/mixed/duplicates so all
# three end up calling tools/traffic_generator/run.sh spoof identically,
# parameterised only by the duplication probability and the foreground
# vs background choice.
_launch_spoof() {
    # _launch_spoof <log-tag> <bg|fg> <dup-prob>
    local tag="$1" sched="$2" dup="$3"
    local interval count
    interval="$(spoof_interval_from_rate "${PACKET_RATE}")"
    count="$(spoof_count_for_duration "${DURATION_SECONDS}" "${PACKET_RATE}")"

    local launcher
    if [[ "${sched}" == "bg" ]]; then launcher=launch_bg; else launcher=launch_fg; fi

    "${launcher}" "${tag}" "${DURATION_SECONDS}" \
        "${RUN_SH}" spoof "${SPOOFED_IFACE}" \
            "${SPOOFED_DST_IP}" "${SPOOFED_DST_PORT}" "${SPOOFED_SRC_IP}" \
            --flows "${SPOOFED_FLOWS}" \
            --count "${count}" \
            --interval "${interval}" \
            --duplication-prob "${dup}"
}

mode_spoofed() {
    # Forged source IP means the receiver's ACKs (if any) go nowhere,
    # the conversation never closes, and openpenny's flow engine sees
    # an open-loop flow -- the closed-loop check fails.
    say "${C_SPOOF}" "spoofed" "sending spoofed packets"
    say "${C_SPOOF}" "spoofed" "source=${SPOOFED_SRC_IP}"
    say "${C_SPOOF}" "spoofed" "destination=${SPOOFED_DST_IP}:${SPOOFED_DST_PORT}"
    say "${C_SPOOF}" "spoofed" "rate=${PACKET_RATE} pps  duration=${DURATION_SECONDS}s  iface=${SPOOFED_IFACE}"
    _launch_spoof "spoofed" fg 0.0
    say "${C_SPOOF}" "spoofed" "done"
}

mode_mixed() {
    # Both flows on the same wire, same destination. openpenny should
    # still reach the CLOSED_LOOP verdict for the legit flow while
    # flagging the spoofed background.
    say "${C_MIX}" "mixed" "starting legitimate traffic first"
    launch_bg "legitimate" "${DURATION_SECONDS}" \
        "${RUN_SH}" client "${LEGIT_DST_HOST}" "${LEGIT_DST_PORT}" \
            --interval "${LEGIT_INTERVAL_SECS}"
    say "${C_MIX}" "mixed" "waiting ${MIXED_STAGGER_SECS}s before adding spoofed background"
    if [[ "${DRY_RUN}" != "1" ]]; then
        sleep "${MIXED_STAGGER_SECS}"
    fi
    say "${C_MIX}" "mixed" "starting spoofed background"
    _launch_spoof "spoofed" bg 0.0
    say "${C_MIX}" "mixed" "both generators running for ${DURATION_SECONDS}s"
    if [[ "${DRY_RUN}" != "1" ]]; then
        wait
    fi
    say "${C_MIX}" "mixed" "summary: legitimate dst=${LEGIT_DST_HOST}:${LEGIT_DST_PORT}, spoofed src=${SPOOFED_SRC_IP} dst=${SPOOFED_DST_IP}:${SPOOFED_DST_PORT} rate=${PACKET_RATE}pps"
    say "${C_MIX}" "mixed" "done"
}

mode_duplicates() {
    # Stresses aggregate analysis: the flow engine's
    # duplicate-fraction threshold is the relevant knob to watch on
    # openpenny's side.
    say "${C_DUP}" "duplicates" "starting duplicate-heavy traffic"
    say "${C_DUP}" "duplicates" "duplicate_rate=${DUPLICATE_RATE}"
    say "${C_DUP}" "duplicates" "duration=${DURATION_SECONDS}s rate=${PACKET_RATE}pps iface=${SPOOFED_IFACE}"
    _launch_spoof "duplicates" fg "${DUPLICATE_RATE}"
    say "${C_DUP}" "duplicates" "done"
}

mode_stop() {
    cleanup
    say "${C_CLEAN}" "cleanup" "all stopped"
}

mode_dry_run() {
    # Dry-run dispatch: with no arg, print every mode. Otherwise print
    # only the requested one. Re-enters the mode_* functions with
    # DRY_RUN=1 set so the same code path produces the announcement.
    DRY_RUN=1
    local target="${1:-all}"
    case "${target}" in
        legitimate|spoofed|mixed|duplicates) "mode_${target}" ;;
        all)
            mode_legitimate
            echo
            mode_spoofed
            echo
            mode_mixed
            echo
            mode_duplicates
            ;;
        *)
            say "${C_SETUP}" "setup" "unknown dry-run target: ${target}"
            exit 2
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

usage() {
    cat <<'EOF'
openpenny demo traffic orchestrator.

Usage:
  ./demo_traffic.sh legitimate
  ./demo_traffic.sh spoofed
  ./demo_traffic.sh mixed
  ./demo_traffic.sh duplicates
  ./demo_traffic.sh dry-run [legitimate|spoofed|mixed|duplicates]
  ./demo_traffic.sh stop

All knobs are env-overridable. Most useful:
  DURATION_SECONDS=60 ./demo_traffic.sh mixed
  PACKET_RATE=200     ./demo_traffic.sh spoofed
  DUPLICATE_RATE=0.8  ./demo_traffic.sh duplicates
  SPOOFED_IFACE=eth1 SPOOFED_SRC_IP=198.51.100.42 ./demo_traffic.sh spoofed

Defaults intentionally use RFC 5737 (198.51.100.0/24, TEST-NET-2) so
an unconfigured run can't aim spoofed traffic at production.
See demo/README.md for the full per-mode setup.
EOF
}

main() {
    local mode="${1:-help}"
    shift || true
    case "${mode}" in
        legitimate) ensure_environment; mode_legitimate ;;
        spoofed)    ensure_environment; mode_spoofed ;;
        mixed)      ensure_environment; mode_mixed ;;
        duplicates) ensure_environment; mode_duplicates ;;
        stop)       mode_stop ;;
        dry-run)    ensure_environment; mode_dry_run "$@" ;;
        help|-h|--help) usage ;;
        *)
            say "${C_SETUP}" "setup" "unknown mode: ${mode}"
            usage
            exit 2
            ;;
    esac
}

main "$@"
