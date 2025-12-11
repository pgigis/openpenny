#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""
Launch a mix of iperf3 client traffic and spoofed flows (via spoofed_client.py).

Usage:
  python3 mixed_traffic.py --iface ens5f0np0 --dst-mac ff:ff:ff:ff:ff:ff \
    --iperf-server 192.0.2.20 --iperf-port 5201 --iperf-parallel 4 \
    --spoof-dest-ip 198.51.100.20 --spoof-dest-port 9000 \
    --spoof-src-ip 198.51.100.10 --spoof-flows 3 --spoof-count 20 --spoof-payload 64 \
    --spoof-interval 0.02 --spoof-jitter 0.01 --spoof-dup-prob 0.1

Notes:
- Requires iperf3 installed on the client host.
- Requires scapy for spoofed flows (see traffic_generator/requirements.txt).
- Spoofed flows are injected at L2 using the existing spoofed_client.py.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_iperf(server: str, port: int, parallel: int, duration: int) -> subprocess.Popen:
    cmd = [
        "iperf3",
        "--client",
        server,
        "--port",
        str(port),
        "--parallel",
        str(parallel),
        "--time",
        str(duration),
    ]
    print(f"[mixed] launching iperf3: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_spoofed(args: argparse.Namespace) -> subprocess.Popen:
    script = Path(__file__).parent / "spoofed_client.py"
    cmd = [
        sys.executable,
        str(script),
        "--iface",
        args.iface,
        "--dst-mac",
        args.dst_mac,
        "--dest-ip",
        args.spoof_dest_ip,
        "--dest-port",
        str(args.spoof_dest_port),
        "--src-ip",
        args.spoof_src_ip,
        "--flows",
        str(args.spoof_flows),
        "--count",
        str(args.spoof_count),
        "--payload-size",
        str(args.spoof_payload),
        "--interval",
        str(args.spoof_interval),
        "--interval-jitter",
        str(args.spoof_jitter),
        "--duplication-prob",
        str(args.spoof_dup_prob),
    ]
    if args.spoof_debug:
        cmd.append("--debug")
    print(f"[mixed] launching spoofed flows: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate mixed iperf + spoofed traffic")

    # iperf settings
    parser.add_argument("--iperf-server", required=True, help="iperf3 server IP")
    parser.add_argument("--iperf-port", type=int, default=5201, help="iperf3 server port")
    parser.add_argument("--iperf-parallel", type=int, default=4, help="Number of parallel iperf streams")
    parser.add_argument("--iperf-duration", type=int, default=30, help="iperf test duration (seconds)")

    # Spoofed flow settings
    parser.add_argument("--iface", required=True, help="Interface for spoofed injection (e.g., ens5f0np0)")
    parser.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff", help="Destination MAC for spoofed flows")
    parser.add_argument("--spoof-dest-ip", required=True, help="Destination IP for spoofed flows")
    parser.add_argument("--spoof-dest-port", type=int, required=True, help="Destination port for spoofed flows")
    parser.add_argument("--spoof-src-ip", required=True, help="Spoofed source IP for spoofed flows")
    parser.add_argument("--spoof-flows", type=int, default=1, help="Number of spoofed flows")
    parser.add_argument("--spoof-count", type=int, default=10, help="Data packets per flow after SYN")
    parser.add_argument("--spoof-payload", type=int, default=48, help="Payload size for spoofed packets")
    parser.add_argument("--spoof-interval", type=float, default=0.0, help="Base interval between spoofed packets")
    parser.add_argument("--spoof-jitter", type=float, default=0.0, help="Interval jitter for spoofed packets")
    parser.add_argument("--spoof-dup-prob", type=float, default=0.0, help="Duplicate probability for spoofed packets")
    parser.add_argument("--spoof-debug", action="store_true", help="Enable debug output for spoofed flows")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    iperf_proc = run_iperf(args.iperf_server, args.iperf_port, args.iperf_parallel, args.iperf_duration)
    spoof_proc = run_spoofed(args)

    # Wait for both to finish; iperf duration dominates runtime.
    iperf_stdout, iperf_stderr = iperf_proc.communicate()
    spoof_stdout, spoof_stderr = spoof_proc.communicate()

    if iperf_stdout:
        sys.stdout.write(iperf_stdout.decode(errors="replace"))
    if iperf_stderr:
        sys.stderr.write(iperf_stderr.decode(errors="replace"))
    if spoof_stdout:
        sys.stdout.write(spoof_stdout.decode(errors="replace"))
    if spoof_stderr:
        sys.stderr.write(spoof_stderr.decode(errors="replace"))

    rc = 0
    if iperf_proc.returncode not in (0, None):
        rc = iperf_proc.returncode
    if spoof_proc.returncode not in (0, None) and rc == 0:
        rc = spoof_proc.returncode
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
