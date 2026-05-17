#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Demo wrapper around tools/traffic_generator/run.sh. Drives four canned
# traffic scenarios (legitimate, spoofed, mixed, duplicates) from a
# single command so a live walkthrough doesn't have to remember every
# flag, and tears the children down cleanly when you're done.
#
# Each scenario opens with a framed banner that names what's being sent
# and the verdict openpenny should reach, so the audience can score the
# other pane in real time. `walkthrough` chains all four with pauses;
# `dry-run` prints the same banners so it doubles as a run-of-show.
#
# Doesn't touch openpenny and doesn't reimplement anything from
# tools/traffic_generator/ -- it only shells out to run.sh, which
# already knows about sudo, the venv, and the Python scripts.
#
# Scenarios:
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
# Control commands:
#
#   walkthrough Run all four scenarios in order with banners and a
#               pause between them. Defaults to press-Enter; pass
#               --auto N (or AUTO_PAUSE_SECS=N) for an N-second sleep
#               so an unattended recording can run end-to-end.
#
#   stop        Terminate every background generator the demo started.
#               Idempotent.
#
#   dry-run     Print the banners and commands that would run, in
#               order, without actually running anything. Optionally
#               takes a scenario name to limit the dump.
#
# Usage:
#   ./demo_traffic.sh legitimate
#   ./demo_traffic.sh spoofed
#   ./demo_traffic.sh mixed
#   ./demo_traffic.sh duplicates
#   ./demo_traffic.sh walkthrough [--auto N]
#   ./demo_traffic.sh dry-run [legitimate|spoofed|mixed|duplicates|walkthrough]
#   ./demo_traffic.sh stop
#
# All knobs in the CONFIG block below can be overridden via env vars,
# e.g.   DURATION_SECONDS=60 PACKET_RATE=200 ./demo_traffic.sh mixed
#
# The defaults intentionally use the RFC 5737 documentation prefixes
# (198.51.100.0/24, TEST-NET-2) so an unconfigured run can't aim
# spoofed traffic at production by accident.

set -euo pipefail

# Enable job control so every backgrounded pipeline gets its OWN
# process group, while still sharing this script's controlling tty.
# Two reasons we need this:
#   1. Clean teardown -- cleanup() does `kill -- -PID` (negative PID =
#      signal entire pgroup). Without job control, `( ... ) &` would
#      inherit the script's pgroup and the recorded PID wouldn't be a
#      valid PGID, so the kill would no-op and iperf3/sudo/sed/tee
#      would survive Ctrl+C.
#   2. Sudo tty_tickets -- sudo's credential cache is keyed by tty.
#      `setsid` would give each bg pipeline a fresh session with no
#      tty, so the cache from our `sudo -v` pre-auth wouldn't apply
#      and the spawned sudo would prompt for a password it can't read.
#      Job-control pgroups keep the same controlling tty, so the
#      cached credentials are honoured.
set -m

# -----------------------------------------------------------------------------
# CONFIG -- override any of these from the environment.
# -----------------------------------------------------------------------------

# Where the legitimate TCP client connects. The receiver host runs server.py
# (or whatever listener you have) on this host:port.
LEGIT_SRC_HOST="${LEGIT_SRC_HOST:-$(hostname)}"   # informational; appears in log lines
LEGIT_DST_HOST="${LEGIT_DST_HOST:-192.168.43.3}"
LEGIT_DST_PORT="${LEGIT_DST_PORT:-5201}"
LEGIT_PARALLEL_STREAMS="${LEGIT_PARALLEL_STREAMS:-16}" # iperf3 -P

# Spoofed-flow knobs. These map onto spoofed_client.py's CLI directly.
SPOOFED_IFACE="${SPOOFED_IFACE:-ens5f1np1}"
SPOOFED_SRC_IP="${SPOOFED_SRC_IP:-198.51.100.10}"
SPOOFED_DST_IP="${SPOOFED_DST_IP:-192.168.43.3}"
SPOOFED_DST_PORT="${SPOOFED_DST_PORT:-5201}"
SPOOFED_FLOWS="${SPOOFED_FLOWS:-30}"
SPOOFED_PAYLOAD_SIZE="${SPOOFED_PAYLOAD_SIZE:-64}"
# Per-flow packet count is randomised uniformly in [MIN, MAX]. Each
# flow runs as its own spoofed_client.py process so the count can vary.
SPOOFED_COUNT_MIN="${SPOOFED_COUNT_MIN:-300}"
SPOOFED_COUNT_MAX="${SPOOFED_COUNT_MAX:-600}"

# Wall-clock cap for any one scenario. The orchestrator runs each
# generator under `timeout`, so this is the only knob you need to bound
# a demo segment cleanly. Also passed as iperf3's -t for legitimate mode.
DURATION_SECONDS="${DURATION_SECONDS:-60}"

# Extra seconds the `timeout` wrapper gets beyond DURATION_SECONDS, so
# iperf3 finishes its test naturally and gets time to exchange FIN +
# results before being terminated. Without this, timeout kills iperf3
# mid-close and some streams die with RST instead of a clean FIN --
# openpenny then doesn't count them as closed-loop flows.
TIMEOUT_GRACE_SECS="${TIMEOUT_GRACE_SECS:-10}"

# Spoofed flow pacing. PACKET_RATE is in packets per second; we convert
# it to spoofed_client.py's --interval below.
PACKET_RATE="${PACKET_RATE:-50}"

# Per-packet duplicate probability for `duplicates` mode. Range [0.0, 1.0].
# spoofed_client.py exposes this as --duplication-prob. 20% is enough
# to comfortably trip openpenny's duplicate-fraction threshold without
# swamping the receiver.
DUPLICATE_RATE="${DUPLICATE_RATE:-0.2}"

# Mixed mode now fires spoofed FIRST, lets the first
# MIXED_SPOOF_LEAD_PACKETS packets land, then starts a small number of
# slow legit iperf3 streams. MIXED_LEGIT_BANDWIDTH is per-stream; "auto"
# computes a value that aggregates to roughly the spoofed throughput
# (PACKET_RATE * SPOOFED_FLOWS * (SPOOFED_PAYLOAD_SIZE + ~54B hdr) * 8)
# so the legit flows don't drown the spoofed traffic out on the wire.
MIXED_SPOOF_LEAD_PACKETS="${MIXED_SPOOF_LEAD_PACKETS:-75}" # in [50, 100]
MIXED_LEGIT_PARALLEL="${MIXED_LEGIT_PARALLEL:-5}"
MIXED_LEGIT_BANDWIDTH="${MIXED_LEGIT_BANDWIDTH:-auto}"     # iperf3 -b, "auto" or "200K"/"1M"/etc.

# Walkthrough pacing.
#   ""  -> press-Enter prompt between scenarios.
#   N   -> sleep N seconds instead. Also set by `walkthrough --auto N`.
AUTO_PAUSE_SECS="${AUTO_PAUSE_SECS:-}"

# -----------------------------------------------------------------------------
# Internal state
# -----------------------------------------------------------------------------

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
TG_DIR="${REPO_ROOT}/tools/traffic_generator"
RUN_SH="${TG_DIR}/run.sh"
TG_VENV_PY="${TG_DIR}/.venv/bin/python"
SPOOFED_SCRIPT="${TG_DIR}/spoofed_client.py"

# State files are per-EUID so a sudo run and a non-sudo run don't
# collide on each other's tee target. If the previous file was created
# by the other user, an "append" tee would die with EACCES, the pipe
# would break, and SIGPIPE would kill the actual traffic generator
# before anything went on the wire.
PID_FILE="${PID_FILE:-/tmp/openpenny-demo-traffic.${EUID}.pids}"
LOG_FILE="${LOG_FILE:-/tmp/openpenny-demo-traffic.${EUID}.log}"
# Markers file: one line per scenario boundary. A tailer on the
# openpenny pane can follow this to line up verdicts with scenario
# starts/ends when scrubbing back through a recording.
MARKERS_FILE="${MARKERS_FILE:-/tmp/openpenny-demo-traffic.${EUID}.markers}"

DRY_RUN="${DRY_RUN:-0}"

# Banner counters. `walkthrough` sets SCENARIO_TOTAL to 4; single-mode
# runs leave it at 1 so the banner reads "[1/1]".
SCENARIO_TOTAL="${SCENARIO_TOTAL:-1}"
SCENARIO_INDEX=0

# ANSI prefixes for the demo prompts. Stripped automatically when the
# shell isn't a TTY (so logs and tee'd output stay clean).
if [[ -t 1 ]]; then
    C_SETUP="\033[36m"   # cyan
    C_LEGIT="\033[32m"   # green
    C_SPOOF="\033[33m"   # yellow
    C_MIX="\033[35m"     # magenta
    C_DUP="\033[31m"     # red
    C_CLEAN="\033[34m"   # blue
    C_BOLD="\033[1m"
    C_DIM="\033[2m"
    C_RST="\033[0m"
else
    C_SETUP=""; C_LEGIT=""; C_SPOOF=""; C_MIX=""; C_DUP=""; C_CLEAN=""
    C_BOLD=""; C_DIM=""; C_RST=""
fi

# 72-char rule used at the top and bottom of every scenario banner.
RULE="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

say() {
    # say <prefix-color> <prefix-tag> <message...>
    local color="$1" tag="$2"; shift 2
    printf "${color}[%s]${C_RST} %s\n" "${tag}" "$*"
}

# -----------------------------------------------------------------------------
# Banner / recap / markers
# -----------------------------------------------------------------------------

# Stamp a scenario boundary into the main log and the sidecar markers
# file. The receiver/openpenny pane can `tail -F` MARKERS_FILE to line
# its verdicts up with scenario boundaries after the fact.
mark_scenario() {
    # mark_scenario <BEGIN|END> <tag> <note...>
    local phase="$1" tag="$2"; shift 2
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local line="=== SCENARIO ${tag} ${phase} ts=${ts} :: $* ==="
    if [[ "${DRY_RUN}" == "1" ]]; then
        printf "%s\n" "${line}"
        return 0
    fi
    mkdir -p "$(dirname "${LOG_FILE}")" "$(dirname "${MARKERS_FILE}")"
    printf "%s\n" "${line}" >> "${LOG_FILE}"
    printf "%s\n" "${line}" >> "${MARKERS_FILE}"
}

# Banner block printed before each scenario runs. Names the scenario,
# what's about to be sent, and the openpenny verdict the audience
# should look for on the other pane.
banner() {
    # banner <color> <tag> <title> <send-line> <expect-line>
    local color="$1" tag="$2" title="$3" send="$4" expect="$5"
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    local progress="[${SCENARIO_INDEX}/${SCENARIO_TOTAL}]"
    printf "\n${color}%s${C_RST}\n" "${RULE}"
    printf "${color}┃${C_RST} ${C_BOLD}%s SCENARIO: %s${C_RST}\n" "${progress}" "${title}"
    printf "${color}┃${C_RST} ${C_DIM}sending:${C_RST} %s\n" "${send}"
    printf "${color}┃${C_RST} ${C_DIM}expect: ${C_RST} %s ${C_DIM}(watch openpenny pane)${C_RST}\n" "${expect}"
    printf "${color}%s${C_RST}\n" "${RULE}"
    mark_scenario "BEGIN" "${tag}" "${title}"
}

# One-line recap printed after each scenario finishes. Mirrors the
# `expect` line on the banner so a recording reviewer can see the
# hypothesis and the close-out next to each other.
recap() {
    # recap <color> <tag> <recap-line...>
    local color="$1" tag="$2"; shift 2
    printf "${color}└─${C_RST} ${C_BOLD}recap${C_RST} ${color}─${C_RST} %s\n" "$*"
    mark_scenario "END" "${tag}" "$*"
}

# Walkthrough pause: wait for Enter, or sleep AUTO_PAUSE_SECS if set,
# or no-op if no TTY (so piped/recorded runs don't hang forever).
walkthrough_pause() {
    # walkthrough_pause <next-scenario-name>
    local next="$1"
    if [[ -n "${AUTO_PAUSE_SECS}" ]]; then
        say "${C_SETUP}" "pause" "auto-pause ${AUTO_PAUSE_SECS}s before: ${next}"
        if [[ "${DRY_RUN}" != "1" ]]; then
            sleep "${AUTO_PAUSE_SECS}"
        fi
        return 0
    fi
    if [[ ! -t 0 ]]; then
        say "${C_SETUP}" "pause" "no TTY for prompt; continuing to: ${next}"
        return 0
    fi
    say "${C_SETUP}" "pause" "press Enter to continue with: ${next}"
    if [[ "${DRY_RUN}" != "1" ]]; then
        # shellcheck disable=SC2034
        read -r _ || true
    fi
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

# Pre-authenticate sudo before any spoofed scenario kicks off. Raw-
# socket injection needs root, and the spoofed fan-out launches
# ${SPOOFED_FLOWS} parallel processes -- without a primed sudo cache
# each one would race to prompt for a password. No-op when already
# root or under DRY_RUN.
ensure_sudo() {
    if [[ "${EUID}" -eq 0 ]]; then
        say "${C_SETUP}" "sudo" "already root; no sudo needed"
        return 0
    fi
    require sudo "sudo"
    say "${C_SETUP}" "sudo" "pre-authenticating sudo (you may be prompted)"
    if [[ "${DRY_RUN}" == "1" ]]; then
        return 0
    fi
    if ! sudo -v; then
        say "${C_SETUP}" "sudo" "sudo authentication failed; spoofed scenarios need root for raw sockets."
        exit 1
    fi
    # Keep the sudo timestamp warm in the background for the full run,
    # so a long duration doesn't lose the cache halfway through.
    ( while kill -0 "$$" 2>/dev/null; do sudo -nv 2>/dev/null || exit; sleep 30; done ) &
    record_pid "$!"
}

ensure_environment() {
    require timeout "GNU coreutils 'timeout'"
    require python3 "Python 3"
    require iperf3 "iperf3"
    # Pre-create state files so tee in the launch_* pipelines never
    # racing-creates them mid-run. If a stale file is owned by a
    # different EUID and we can't touch it, fail loud rather than
    # letting SIGPIPE silently kill children later.
    local f
    for f in "${LOG_FILE}" "${MARKERS_FILE}" "${PID_FILE}"; do
        mkdir -p "$(dirname "${f}")"
        if ! ( : >> "${f}" ) 2>/dev/null; then
            say "${C_SETUP}" "setup" "cannot write to ${f}; remove it or set LOG_FILE/MARKERS_FILE/PID_FILE in env."
            exit 1
        fi
    done
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

# Per-stream bps that aggregates to roughly the spoofed wire rate
# (PACKET_RATE * SPOOFED_FLOWS * (payload + ~54B TCP/IP hdr) * 8) when
# divided across N legit streams. Bottoms out at 1 so iperf3 doesn't
# choke on -b 0.
compute_auto_bandwidth() {
    local streams="${1}"
    local spoof_bps per_stream_bps
    spoof_bps=$(( PACKET_RATE * SPOOFED_FLOWS * (SPOOFED_PAYLOAD_SIZE + 54) * 8 ))
    per_stream_bps=$(( spoof_bps / streams ))
    (( per_stream_bps < 1 )) && per_stream_bps=1
    printf "%d" "${per_stream_bps}"
}

# Resolve an iperf3 bandwidth spec: pass through "100K"/"1M"/etc. as-is,
# expand "auto" via compute_auto_bandwidth. Empty input -> empty output
# (caller will omit -b).
resolve_bandwidth() {
    local spec="${1}" streams="${2}"
    if [[ -z "${spec}" ]]; then
        printf ""
    elif [[ "${spec}" == "auto" ]]; then
        compute_auto_bandwidth "${streams}"
    else
        printf "%s" "${spec}"
    fi
}

# Launch an iperf3 client. Always runs unprivileged: if we were entered
# via sudo (EUID 0 with SUDO_USER set) drop back to the original user
# so iperf3 doesn't pointlessly run as root. The spoofed generator is
# the only thing that legitimately needs root in this script.
#
# launch_legit_iperf3 <log-tag> <bg|fg> <parallel-streams> <bandwidth-spec>
#   bandwidth-spec: "auto", a literal iperf3 -b value, or "" for no cap.
launch_legit_iperf3() {
    local tag="$1" sched="$2" parallel="$3" bw_spec="${4:-}"
    local launcher
    if [[ "${sched}" == "bg" ]]; then launcher=launch_bg; else launcher=launch_fg; fi

    local bandwidth
    bandwidth="$(resolve_bandwidth "${bw_spec}" "${parallel}")"

    local cmd=(iperf3 -c "${LEGIT_DST_HOST}" -p "${LEGIT_DST_PORT}"
               -P "${parallel}" -Z -t "${DURATION_SECONDS}")
    if [[ -n "${bandwidth}" ]]; then
        cmd+=(-b "${bandwidth}")
    fi
    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
        cmd=(sudo -u "${SUDO_USER}" "${cmd[@]}")
    fi

    # Give the timeout wrapper more headroom than iperf3's -t so iperf3
    # finishes the test naturally and exchanges FIN + results before
    # being killed. Without the grace, `timeout 60s iperf3 -t 60` would
    # SIGTERM iperf3 mid-close and some streams would die with RST --
    # openpenny then wouldn't count them as closed-loop flows ("iperf3:
    # interrupt - the client has terminated").
    local hard_cap=$(( DURATION_SECONDS + TIMEOUT_GRACE_SECS ))
    "${launcher}" "${tag}" "${hard_cap}" "${cmd[@]}"
}

record_pid() {
    local pid="$1"
    mkdir -p "$(dirname "${PID_FILE}")"
    echo "${pid}" >> "${PID_FILE}"
}

# Run a command in the background under `timeout`, log its stdout/stderr,
# and remember its PID for later cleanup. Honours DRY_RUN.
#
# Because `set -m` is on, the `( ... ) &` subshell becomes the leader
# of its own process group whose PGID equals the subshell PID we
# record. cleanup() can then signal `-PID` to take down the whole
# group (timeout, the real command, sed, tee, and any sudo wrapper)
# in one shot, instead of just the subshell.
launch_bg() {
    # launch_bg <log-tag> <duration> <cmd...>
    local tag="$1" duration="$2"; shift 2
    if [[ "${DRY_RUN}" == "1" ]]; then
        printf "[dry-run %s]  timeout %ss %s\n" "${tag}" "${duration}" "$*"
        return 0
    fi
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
    local pid
    # Each recorded PID is the leader of a process group we created
    # via setsid in launch_bg. `kill -- -PID` (negative PID) signals
    # the entire group at once -- so timeout, sed, tee, sudo, and the
    # actual python/iperf3 all get hit, not just the bash subshell at
    # the top. Fall back to a bare-PID signal for entries recorded
    # without setsid (e.g. the sudo keep-warm loop in ensure_sudo).
    while read -r pid; do
        [[ -z "${pid}" ]] && continue
        kill -TERM -- "-${pid}" 2>/dev/null \
            || kill -TERM "${pid}" 2>/dev/null \
            || true
    done < "${PID_FILE}"
    # Give them a moment, then force.
    sleep 1
    while read -r pid; do
        [[ -z "${pid}" ]] && continue
        kill -KILL -- "-${pid}" 2>/dev/null \
            || kill -KILL "${pid}" 2>/dev/null \
            || true
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
    # Real SYN, real ACKs from the receiver, payload, clean FIN, across
    # ${LEGIT_PARALLEL_STREAMS} parallel iperf3 streams. openpenny should
    # reach a CLOSED_LOOP verdict on these flows.
    banner "${C_LEGIT}" "legitimate" \
        "legitimate (closed-loop control)" \
        "iperf3 ${LEGIT_SRC_HOST} -> ${LEGIT_DST_HOST}:${LEGIT_DST_PORT}, -P ${LEGIT_PARALLEL_STREAMS} -Z -t ${DURATION_SECONDS}" \
        "CLOSED_LOOP verdict on the flow(s)"
    launch_legit_iperf3 "legitimate" fg "${LEGIT_PARALLEL_STREAMS}" ""
    recap "${C_LEGIT}" "legitimate" \
        "ran iperf3 -P ${LEGIT_PARALLEL_STREAMS} -Z -t ${DURATION_SECONDS} to ${LEGIT_DST_HOST}:${LEGIT_DST_PORT}; openpenny pane should show CLOSED_LOOP."
}

# Internal: spoofed launcher shared by spoofed/mixed/duplicates. Fires
# ${SPOOFED_FLOWS} parallel spoofed_client.py instances (one per flow),
# each with --flows 1 and a per-flow random --count in
# [SPOOFED_COUNT_MIN, SPOOFED_COUNT_MAX]. This is the only way to get
# per-flow random packet counts: spoofed_client.py's --count is shared
# across all flows in a single invocation.
#
# Runs the venv python directly, under `sudo -E` only when we're not
# already root. `--preflight` is only attached to flow #1 so we get one
# round of diagnostics without 30 copies of it spamming the console.
_launch_spoof() {
    # _launch_spoof <log-tag> <bg|fg> <dup-prob>
    local tag="$1" sched="$2" dup="$3"
    local interval
    interval="$(spoof_interval_from_rate "${PACKET_RATE}")"

    # Pick the venv python; fall back to plain python3 if the venv
    # hasn't been created yet (ensure_environment nudges run.sh install
    # in that case, but stay defensive).
    local py="${TG_VENV_PY}"
    if [[ ! -x "${py}" ]]; then
        py="$(command -v python3 || true)"
    fi

    # Raw-socket injection needs root; preserve env so the venv's
    # site-packages (scapy) stay importable.
    local sudo_prefix=()
    if [[ "${EUID}" -ne 0 ]]; then
        sudo_prefix=(sudo -E)
    fi

    local span=$(( SPOOFED_COUNT_MAX - SPOOFED_COUNT_MIN + 1 ))
    if (( span <= 0 )); then span=1; fi

    local i count preflight_arg
    for (( i = 1; i <= SPOOFED_FLOWS; i++ )); do
        count=$(( SPOOFED_COUNT_MIN + RANDOM % span ))
        if (( i == 1 )); then
            preflight_arg="--preflight"
        else
            preflight_arg=""
        fi
        # Always launch into the background so all flows run concurrently;
        # the caller's `sched=fg` semantics are honoured by waiting at
        # the end of this function.
        launch_bg "${tag}#${i}" "${DURATION_SECONDS}" \
            "${sudo_prefix[@]}" "${py}" "${SPOOFED_SCRIPT}" \
                --iface "${SPOOFED_IFACE}" \
                --routed \
                --dest-ip "${SPOOFED_DST_IP}" \
                --dest-port "${SPOOFED_DST_PORT}" \
                --src-ip "${SPOOFED_SRC_IP}" \
                --flows 1 \
                --count "${count}" \
                --payload-size "${SPOOFED_PAYLOAD_SIZE}" \
                --interval "${interval}" \
                --duplication-prob "${dup}" \
                ${preflight_arg}
    done

    # For fg semantics (caller wants this call to block), wait for the
    # whole fan-out to finish. For bg (mixed mode), return now and let
    # the caller's own `wait` cover everything.
    if [[ "${sched}" == "fg" && "${DRY_RUN}" != "1" ]]; then
        wait
    fi
}

mode_spoofed() {
    # Forged source IP means the receiver's ACKs (if any) go nowhere,
    # the conversation never closes, and openpenny's flow engine sees
    # open-loop flows -- the closed-loop check fails on each one.
    # Spoofed-only by design: no legit iperf3 side-channel here, so the
    # aggregate forged_src -> dest is entirely open-loop. mode_mixed is
    # the variant that intentionally adds legit flows on the wire.
    ensure_sudo
    banner "${C_SPOOF}" "spoofed" \
        "spoofed (forged source IP, spoofed-only)" \
        "${SPOOFED_FLOWS} spoofed @ ${PACKET_RATE}pps src=${SPOOFED_SRC_IP} -> ${SPOOFED_DST_IP}:${SPOOFED_DST_PORT}" \
        "closed-loop FAILS on the ${SPOOFED_FLOWS} spoofed flows (no legit traffic on the wire)"

    say "${C_SPOOF}" "spoofed" "starting spoofed fan-out (${SPOOFED_FLOWS} flows, sudo)"
    _launch_spoof "spoofed" fg 0.0
    recap "${C_SPOOF}" "spoofed" \
        "${SPOOFED_FLOWS} spoofed flows only; openpenny pane should show open-loop on the forged_src -> dest aggregate."
}

mode_mixed() {
    ensure_sudo
    # Spoofed fires first. After the first MIXED_SPOOF_LEAD_PACKETS
    # packets have had time to land on the wire (lead = N / PACKET_RATE
    # seconds), we add ${MIXED_LEGIT_PARALLEL} slow iperf3 streams
    # whose aggregate bandwidth roughly matches the spoofed throughput
    # -- so the legit flows can't drown the spoofed traffic out for
    # openpenny's flow engine.
    local lead_secs bandwidth_arg spoof_bps per_stream_bps
    lead_secs="$(awk -v p="${MIXED_SPOOF_LEAD_PACKETS}" -v r="${PACKET_RATE}" \
        'BEGIN { if (r > 0) printf "%.2f", p / r; else printf "0.0"; }')"

    if [[ "${MIXED_LEGIT_BANDWIDTH}" == "auto" ]]; then
        # Wire-rate estimate per spoofed packet: payload + ~54B TCP/IP
        # headers. Aggregate across all spoofed flows, then split evenly
        # across the legit streams. Bottom out at 1 bps so iperf3
        # doesn't choke on -b 0.
        spoof_bps=$(( PACKET_RATE * SPOOFED_FLOWS * (SPOOFED_PAYLOAD_SIZE + 54) * 8 ))
        per_stream_bps=$(( spoof_bps / MIXED_LEGIT_PARALLEL ))
        (( per_stream_bps < 1 )) && per_stream_bps=1
        bandwidth_arg="${per_stream_bps}"
    else
        bandwidth_arg="${MIXED_LEGIT_BANDWIDTH}"
    fi

    banner "${C_MIX}" "mixed" \
        "mixed (spoofed first, then matched-rate legit)" \
        "spoofed ${SPOOFED_FLOWS} flows @ ${PACKET_RATE}pps src=${SPOOFED_SRC_IP}; after ~${lead_secs}s, iperf3 -P ${MIXED_LEGIT_PARALLEL} -b ${bandwidth_arg} -> ${LEGIT_DST_HOST}:${LEGIT_DST_PORT}" \
        "CLOSED_LOOP for the legit half; closed-loop check FAILS for spoofed"

    say "${C_MIX}" "mixed" "starting spoofed fan-out first (${SPOOFED_FLOWS} flows)"
    _launch_spoof "spoofed" bg 0.0

    say "${C_MIX}" "mixed" \
        "waiting ~${lead_secs}s (${MIXED_SPOOF_LEAD_PACKETS} pkts @ ${PACKET_RATE}pps) before legit kicks in"
    if [[ "${DRY_RUN}" != "1" ]]; then
        sleep "${lead_secs}"
    fi

    say "${C_MIX}" "mixed" \
        "starting ${MIXED_LEGIT_PARALLEL} slow legit flows (-b ${bandwidth_arg} per stream, unprivileged)"
    launch_legit_iperf3 "legitimate" bg "${MIXED_LEGIT_PARALLEL}" "${bandwidth_arg}"

    say "${C_MIX}" "mixed" "both generators running"
    if [[ "${DRY_RUN}" != "1" ]]; then
        wait
    fi
    recap "${C_MIX}" "mixed" \
        "spoofed first then ${MIXED_LEGIT_PARALLEL} matched-rate legit flows; openpenny pane should show CLOSED_LOOP only for the legit half."
}

mode_duplicates() {
    # Stresses aggregate analysis: the flow engine's
    # duplicate-fraction threshold is the relevant knob to watch on
    # openpenny's side. Same fan-out as spoofed mode, but every spoofed
    # flow carries the duplicate-probability dial. NO legit iperf3
    # flows here -- this scenario is intentionally spoofed-only so the
    # duplicate-fraction reading isn't diluted by clean closed-loop
    # traffic on the aggregate.
    ensure_sudo
    banner "${C_DUP}" "duplicates" \
        "duplicates (duplicate-heavy spoofed only)" \
        "${SPOOFED_FLOWS} spoofed @ ${PACKET_RATE}pps dup-prob=${DUPLICATE_RATE} on ${SPOOFED_IFACE}" \
        "duplicate-fraction threshold trips on the spoofed aggregate"
    _launch_spoof "duplicates" fg "${DUPLICATE_RATE}"
    recap "${C_DUP}" "duplicates" \
        "${SPOOFED_FLOWS} duplicate-heavy spoofed flows (dup-prob=${DUPLICATE_RATE}); openpenny pane should show duplicate-fraction threshold tripped."
}

mode_walkthrough() {
    # Run all four scenarios in order with banners and a pause between
    # them. Updates SCENARIO_TOTAL so the banner counter shows progress.
    SCENARIO_TOTAL=4
    SCENARIO_INDEX=0
    local pause_desc
    if [[ -n "${AUTO_PAUSE_SECS}" ]]; then
        pause_desc="${AUTO_PAUSE_SECS}s auto"
    else
        pause_desc="press Enter"
    fi
    say "${C_SETUP}" "walkthrough" "running all 4 scenarios. Pause between each: ${pause_desc}."
    say "${C_SETUP}" "walkthrough" "markers will land in ${MARKERS_FILE}"
    mode_legitimate
    walkthrough_pause "spoofed"
    mode_spoofed
    walkthrough_pause "mixed"
    mode_mixed
    walkthrough_pause "duplicates"
    mode_duplicates
    say "${C_SETUP}" "walkthrough" "all scenarios complete."
}

mode_stop() {
    cleanup
    say "${C_CLEAN}" "cleanup" "all stopped"
}

mode_dry_run() {
    # Dry-run dispatch: with no arg (or `walkthrough`/`all`), print
    # every scenario with banners. Otherwise print only the requested
    # one. Re-enters the mode_* functions with DRY_RUN=1 set so the
    # same code path produces the announcement.
    DRY_RUN=1
    local target="${1:-all}"
    case "${target}" in
        legitimate|spoofed|mixed|duplicates)
            SCENARIO_TOTAL=1
            SCENARIO_INDEX=0
            "mode_${target}"
            ;;
        all|walkthrough)
            SCENARIO_TOTAL=4
            SCENARIO_INDEX=0
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
    cat <<EOF
openpenny demo traffic orchestrator.

Scenarios:
  ./demo_traffic.sh legitimate
  ./demo_traffic.sh spoofed
  ./demo_traffic.sh mixed
  ./demo_traffic.sh duplicates

Control commands:
  ./demo_traffic.sh walkthrough [--auto N]
  ./demo_traffic.sh dry-run [legitimate|spoofed|mixed|duplicates|walkthrough]
  ./demo_traffic.sh stop

Each scenario prints a framed banner with the expected openpenny
verdict and a one-line recap when it finishes. Scenario boundary
markers land in ${MARKERS_FILE}.

All knobs are env-overridable. Most useful:
  DURATION_SECONDS=60 ./demo_traffic.sh mixed
  PACKET_RATE=200     ./demo_traffic.sh spoofed
  DUPLICATE_RATE=0.8  ./demo_traffic.sh duplicates
  AUTO_PAUSE_SECS=5   ./demo_traffic.sh walkthrough
  SPOOFED_IFACE=eth1 SPOOFED_SRC_IP=198.51.100.42 ./demo_traffic.sh spoofed

Defaults intentionally use RFC 5737 (198.51.100.0/24, TEST-NET-2) so
an unconfigured run can't aim spoofed traffic at production.
See demo/README.md for the full per-scenario setup.
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
        walkthrough)
            # Parse --auto N / --auto=N.
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --auto)
                        shift
                        AUTO_PAUSE_SECS="${1:-}"
                        if [[ -z "${AUTO_PAUSE_SECS}" ]]; then
                            say "${C_SETUP}" "setup" "--auto requires N seconds"
                            exit 2
                        fi
                        shift
                        ;;
                    --auto=*)
                        AUTO_PAUSE_SECS="${1#--auto=}"
                        shift
                        ;;
                    *)
                        say "${C_SETUP}" "setup" "unknown walkthrough arg: $1"
                        exit 2
                        ;;
                esac
            done
            ensure_environment
            mode_walkthrough
            ;;
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
