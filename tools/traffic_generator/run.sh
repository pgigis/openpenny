#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Friendly wrapper around the traffic_generator scripts.
# Handles sudo, virtualenv activation, and provides short subcommands.
#
# Quick examples:
#   ./run.sh install                    # set up .venv with scapy
#   ./run.sh server 9000                # run server.py on :9000
#   ./run.sh client 192.0.2.1 9000      # run client.py against host:port
#   ./run.sh doctor ens5f0np0 192.168.43.3 198.51.100.10
#                                        # run preflight.py only, no traffic
#   ./run.sh spoof ens5f0np0 192.168.43.3 5201 198.51.100.10
#                                        # routed-mode spoof with sane defaults
#   ./run.sh spoof-l2 ens5f0np0 aa:bb:cc:dd:ee:ff 192.0.2.10 9000 198.51.100.10
#                                        # L2 inject with a unicast MAC
#   ./run.sh mixed ens5f0np0 192.0.2.20 198.51.100.20 198.51.100.10
#                                        # iperf3 + spoofed flows in parallel
#
# Any extra flags after the positional args are forwarded to the underlying
# Python script unchanged, e.g.
#   ./run.sh spoof ens5f0np0 192.168.43.3 5201 198.51.100.10 \
#            --flows 10 --count 150 --payload-size 64 --debug

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${HERE}/.venv"
PY_BIN="${PYTHON:-python3}"

# Default lab-friendly knobs (override with env vars).
DEFAULT_FLOWS="${DEFAULT_FLOWS:-1}"
DEFAULT_COUNT="${DEFAULT_COUNT:-20}"
DEFAULT_PAYLOAD="${DEFAULT_PAYLOAD:-64}"
DEFAULT_IPERF_PORT="${DEFAULT_IPERF_PORT:-5201}"
DEFAULT_IPERF_PARALLEL="${DEFAULT_IPERF_PARALLEL:-4}"
DEFAULT_IPERF_DURATION="${DEFAULT_IPERF_DURATION:-30}"

usage() {
    cat <<'EOF'
Friendly wrapper around the traffic_generator scripts.
Handles sudo, virtualenv activation, and provides short subcommands.

Quick examples:
  ./run.sh install                    # set up .venv with scapy
  ./run.sh server 9000                # run server.py on :9000
  ./run.sh client 192.0.2.1 9000      # run client.py against host:port
  ./run.sh doctor ens5f0np0 192.168.43.3 198.51.100.10
                                      # run preflight.py only, no traffic
  ./run.sh spoof ens5f0np0 192.168.43.3 5201 198.51.100.10
                                      # routed-mode spoof with sane defaults
  ./run.sh spoof-l2 ens5f0np0 aa:bb:cc:dd:ee:ff 192.0.2.10 9000 198.51.100.10
                                      # L2 inject with a unicast MAC
  ./run.sh mixed ens5f0np0 192.0.2.20 198.51.100.20 198.51.100.10
                                      # iperf3 + spoofed flows in parallel

Any extra flags after the positional args are forwarded to the underlying
Python script unchanged, e.g.
  ./run.sh spoof ens5f0np0 192.168.43.3 5201 198.51.100.10 \
           --flows 10 --count 150 --payload-size 64 --debug
EOF
    cat <<EOF

Subcommands:
  install                              Create .venv and install requirements.
  server <port> [extra...]             Run server.py.
  client <host> <port> [extra...]      Run client.py.
  doctor <iface> <dest-ip> <src-ip> [extra...]
                                       Run preflight diagnostics only.
  spoof  <iface> <dest-ip> <dest-port> <src-ip> [extra...]
                                       Routed mode (kernel picks the route).
  spoof-l2 <iface> <dst-mac> <dest-ip> <dest-port> <src-ip> [extra...]
                                       L2 mode (raw Ethernet, you set dst MAC).
  mixed  <iface> <iperf-server> <spoof-dest-ip> <spoof-src-ip> [extra...]
                                       iperf3 + spoofed flows together.
  help                                 Print this help.

Environment overrides:
  DEFAULT_FLOWS=$DEFAULT_FLOWS DEFAULT_COUNT=$DEFAULT_COUNT
  DEFAULT_PAYLOAD=$DEFAULT_PAYLOAD DEFAULT_IPERF_PORT=$DEFAULT_IPERF_PORT
  DEFAULT_IPERF_PARALLEL=$DEFAULT_IPERF_PARALLEL DEFAULT_IPERF_DURATION=$DEFAULT_IPERF_DURATION
  PYTHON=python3.11 ./run.sh ...
EOF
}

ensure_venv() {
    if [[ -x "${VENV}/bin/python" ]]; then
        return
    fi
    echo "[run.sh] creating virtualenv at ${VENV}"
    "${PY_BIN}" -m venv "${VENV}"
    # shellcheck disable=SC1091
    source "${VENV}/bin/activate"
    pip install --upgrade pip >/dev/null
    pip install -r "${HERE}/requirements.txt"
    deactivate
}

# Build the python invocation. Use sudo only when raw sockets are needed.
# We point sudo at the venv's python so scapy is importable.
py_in_venv() {
    local need_sudo="$1"; shift
    local py="${VENV}/bin/python"
    if [[ ! -x "${py}" ]]; then
        py="${PY_BIN}"
    fi
    if [[ "${need_sudo}" == "1" && "${EUID}" -ne 0 ]]; then
        # Preserve PYTHONPATH so the venv's site-packages stays visible.
        sudo -E "${py}" "$@"
    else
        "${py}" "$@"
    fi
}

cmd_install() {
    ensure_venv
    echo "[run.sh] virtualenv ready: ${VENV}"
    echo "[run.sh] activate with: source ${VENV}/bin/activate"
}

cmd_server() {
    local port="${1:?port required}"
    shift
    py_in_venv 0 "${HERE}/server.py" --host 0.0.0.0 --port "${port}" "$@"
}

cmd_client() {
    local host="${1:?host required}"
    local port="${2:?port required}"
    shift 2
    py_in_venv 0 "${HERE}/client.py" --host "${host}" --port "${port}" "$@"
}

cmd_doctor() {
    local iface="${1:?iface required}"
    local dest_ip="${2:?dest-ip required}"
    local src_ip="${3:?src-ip required}"
    shift 3
    py_in_venv 1 "${HERE}/preflight.py" \
        --iface "${iface}" \
        --dest-ip "${dest_ip}" \
        --src-ip "${src_ip}" \
        "$@"
}

cmd_spoof() {
    local iface="${1:?iface required}"
    local dest_ip="${2:?dest-ip required}"
    local dest_port="${3:?dest-port required}"
    local src_ip="${4:?src-ip required}"
    shift 4
    ensure_venv
    py_in_venv 1 "${HERE}/spoofed_client.py" \
        --iface "${iface}" \
        --routed \
        --dest-ip "${dest_ip}" \
        --dest-port "${dest_port}" \
        --src-ip "${src_ip}" \
        --flows "${DEFAULT_FLOWS}" \
        --count "${DEFAULT_COUNT}" \
        --payload-size "${DEFAULT_PAYLOAD}" \
        --preflight \
        "$@"
}

cmd_spoof_l2() {
    local iface="${1:?iface required}"
    local dst_mac="${2:?dst-mac required}"
    local dest_ip="${3:?dest-ip required}"
    local dest_port="${4:?dest-port required}"
    local src_ip="${5:?src-ip required}"
    shift 5
    ensure_venv
    py_in_venv 1 "${HERE}/spoofed_client.py" \
        --iface "${iface}" \
        --dst-mac "${dst_mac}" \
        --dest-ip "${dest_ip}" \
        --dest-port "${dest_port}" \
        --src-ip "${src_ip}" \
        --flows "${DEFAULT_FLOWS}" \
        --count "${DEFAULT_COUNT}" \
        --payload-size "${DEFAULT_PAYLOAD}" \
        --preflight \
        "$@"
}

cmd_mixed() {
    local iface="${1:?iface required}"
    local iperf_server="${2:?iperf-server required}"
    local spoof_dest_ip="${3:?spoof-dest-ip required}"
    local spoof_src_ip="${4:?spoof-src-ip required}"
    shift 4
    ensure_venv
    py_in_venv 1 "${HERE}/mixed_traffic.py" \
        --iface "${iface}" \
        --iperf-server "${iperf_server}" \
        --iperf-port "${DEFAULT_IPERF_PORT}" \
        --iperf-parallel "${DEFAULT_IPERF_PARALLEL}" \
        --iperf-duration "${DEFAULT_IPERF_DURATION}" \
        --spoof-dest-ip "${spoof_dest_ip}" \
        --spoof-dest-port "${DEFAULT_IPERF_PORT}" \
        --spoof-src-ip "${spoof_src_ip}" \
        --spoof-flows "${DEFAULT_FLOWS}" \
        --spoof-count "${DEFAULT_COUNT}" \
        --spoof-payload "${DEFAULT_PAYLOAD}" \
        "$@"
}

main() {
    local sub="${1:-help}"
    shift || true
    case "${sub}" in
        install)   cmd_install ;;
        server)    cmd_server "$@" ;;
        client)    cmd_client "$@" ;;
        doctor)    cmd_doctor "$@" ;;
        spoof)     cmd_spoof "$@" ;;
        spoof-l2)  cmd_spoof_l2 "$@" ;;
        mixed)     cmd_mixed "$@" ;;
        help|-h|--help) usage ;;
        *)
            echo "[run.sh] unknown subcommand: ${sub}" >&2
            usage
            exit 2
            ;;
    esac
}

main "$@"
