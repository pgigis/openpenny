#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""Preflight diagnostics for the spoofed traffic generator.

Spoofed-source TCP packets often look like they're being sent fine on the
sender (sendp() / raw socket return success), yet never appear at the
receiving application. The most frequent reasons are:

  1. Reverse-path filter on the *receiver* drops packets whose source IP is
     not reachable through the arrival interface (rp_filter=1, strict mode).
  2. Reverse-path filter on the *sender* drops the packet at egress.
  3. The kernel/firewall on the sender drops the packet in the OUTPUT or
     POSTROUTING chains (e.g. nftables / iptables rules, or a firewalld
     "drop non-local source" zone).
  4. An upstream router applies BCP38 / ingress source-address validation
     and drops the spoofed source.
  5. With L2 injection (--dst-mac broadcast), the destination NIC ignores
     TCP frames that are not unicast to it (the kernel never delivers them
     to a TCP socket because the destination MAC is broadcast).
  6. ARP/neighbour resolution to the next hop has not yet completed (first
     packet of a flow gets dropped while the kernel resolves the neighbour).

This module collects facts about the host and prints actionable warnings.
It never modifies system state. It can be used as:

    python3 preflight.py --iface ens5f0np0 --dest-ip 192.168.43.3 \
        --src-ip 198.51.100.10 --routed

or imported and called as:

    from preflight import run_preflight
    issues = run_preflight(iface=..., dest_ip=..., src_ip=..., routed=...)
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


# ANSI colours; disabled if stdout is not a TTY.
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
RED = "\033[31m" if _COLOR else ""
YEL = "\033[33m" if _COLOR else ""
GRN = "\033[32m" if _COLOR else ""
DIM = "\033[2m" if _COLOR else ""
BLD = "\033[1m" if _COLOR else ""
RST = "\033[0m" if _COLOR else ""


@dataclass
class PreflightReport:
    fatal: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    def add_fatal(self, msg: str) -> None:
        self.fatal.append(msg)

    def add_warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_info(self, msg: str) -> None:
        self.info.append(msg)

    def print(self) -> None:
        if self.info:
            print(f"{BLD}Diagnostics{RST}")
            for m in self.info:
                print(f"  {DIM}info{RST}    {m}")
        if self.warnings:
            print(f"{BLD}Warnings{RST}")
            for m in self.warnings:
                print(f"  {YEL}warn{RST}    {m}")
        if self.fatal:
            print(f"{BLD}Errors{RST}")
            for m in self.fatal:
                print(f"  {RED}error{RST}   {m}")
        if not (self.info or self.warnings or self.fatal):
            print(f"{GRN}preflight: nothing to report{RST}")


def _read_proc(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def _run(cmd: List[str], timeout: float = 2.0):
    """Run a command and return (stdout, stderr, rc).

    Returns (None, None, None) only if the command itself could not be
    invoked (binary missing or timed out). Otherwise stdout/stderr are the
    captured streams (stripped) and rc is the exit status.
    """
    try:
        out = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, None, None
    return (out.stdout or "").strip(), (out.stderr or "").strip(), out.returncode


def _run_stdout(cmd: List[str], timeout: float = 2.0) -> Optional[str]:
    """Backwards-compatible wrapper: returns stdout on rc==0, else None."""
    stdout, _stderr, rc = _run(cmd, timeout=timeout)
    if rc != 0 or stdout is None:
        return None
    return stdout


def _check_interface(iface: str, report: PreflightReport) -> None:
    """Verify that the interface exists and is up."""
    try:
        socket.if_nametoindex(iface)
    except OSError:
        names = ", ".join(n for _, n in socket.if_nameindex())
        report.add_fatal(
            f"interface {iface!r} not found"
            + (f"; available: {names}" if names else "")
        )
        return

    operstate = _read_proc(f"/sys/class/net/{iface}/operstate")
    carrier = _read_proc(f"/sys/class/net/{iface}/carrier")
    if operstate and operstate != "up":
        report.add_warn(
            f"{iface}: operstate={operstate} (interface is not up; "
            f"run `sudo ip link set {iface} up`)"
        )
    if carrier == "0":
        report.add_warn(f"{iface}: no carrier (cable unplugged or peer down)")
    else:
        report.add_info(
            f"{iface}: operstate={operstate or '?'}, carrier={carrier or '?'}"
        )


def _check_rp_filter(iface: str, report: PreflightReport) -> None:
    """Check Reverse Path Filtering on the egress interface and globally.

    Linux applies the maximum of conf.<iface>.rp_filter and conf.all.rp_filter.
    Strict mode (1) drops packets whose source IP is not reachable through
    the same interface — which is exactly what spoofed traffic looks like.
    """
    iface_rp = _read_proc(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter")
    all_rp = _read_proc("/proc/sys/net/ipv4/conf/all/rp_filter")
    default_rp = _read_proc("/proc/sys/net/ipv4/conf/default/rp_filter")

    def label(v: Optional[str]) -> str:
        if v == "0":
            return "off"
        if v == "1":
            return "strict"
        if v == "2":
            return "loose"
        return v or "?"

    report.add_info(
        f"rp_filter: {iface}={label(iface_rp)}, "
        f"all={label(all_rp)}, default={label(default_rp)}"
    )

    effective = max(int(iface_rp or 0), int(all_rp or 0))
    if effective == 1:
        report.add_warn(
            "rp_filter is strict on the sender. The kernel may drop locally "
            "generated packets whose source IP is not reachable through the "
            "egress interface. To experiment, switch to loose mode:\n"
            f"        sudo sysctl -w net.ipv4.conf.all.rp_filter=2\n"
            f"        sudo sysctl -w net.ipv4.conf.{iface}.rp_filter=2"
        )
    elif effective == 2:
        report.add_info(
            "rp_filter is loose on the sender (acceptable for spoofed lab traffic)."
        )


def _check_local_source_ip(src_ip: Optional[str], iface: str, report: PreflightReport) -> None:
    """Warn if --src-ip is actually a local address (not really spoofed)."""
    if not src_ip:
        return
    addrs = _run_stdout(["ip", "-4", "-o", "addr", "show", "dev", iface]) or ""
    iface_ips = re.findall(r"inet\s+([\d.]+)/", addrs)
    if src_ip in iface_ips:
        report.add_info(
            f"--src-ip {src_ip} is already configured on {iface}; "
            "this is not technically spoofing."
        )
        return

    # Check whether src_ip is bound on any interface.
    all_addrs = _run_stdout(["ip", "-4", "-o", "addr"]) or ""
    if re.search(rf"\binet\s+{re.escape(src_ip)}/", all_addrs):
        report.add_warn(
            f"--src-ip {src_ip} is configured on a different interface than "
            f"--iface {iface}. The kernel may rewrite or drop the packet."
        )


def _check_destination_route(dest_ip: str, src_ip: Optional[str], iface: str,
                             report: PreflightReport) -> None:
    """Use `ip route get` to see how the kernel will route the destination.

    We deliberately *do not* pass `from <src_ip>` here. That form asks the
    kernel "how would I forward an inbound packet from <src_ip>?" — which for
    a non-local (spoofed) source typically fails with `RTNETLINK answers:
    Network is unreachable` or `Invalid cross-device link`, even though the
    output path for a locally generated packet is perfectly fine. The
    locally-generated path is what the spoofed_client actually exercises, so
    that's what we look up. The forwarding-path probe is reported separately.
    """
    stdout, stderr, rc = _run(["ip", "route", "get", dest_ip])
    if rc is None:
        report.add_warn(
            "`ip` (iproute2) is not installed or timed out; "
            "skipping route lookup."
        )
        return
    if rc != 0 or not stdout:
        msg = stderr or "no output"
        report.add_warn(
            f"`ip route get {dest_ip}` failed: {msg}. "
            "The destination may not be routable from this host."
        )
        return

    first_line = stdout.splitlines()[0]
    report.add_info(f"route: {first_line}")

    m = re.search(r"\bdev\s+(\S+)", first_line)
    if m and m.group(1) != iface:
        report.add_warn(
            f"kernel would normally egress {dest_ip} via {m.group(1)}, "
            f"but you asked for --iface {iface}. With --routed and "
            f"SO_BINDTODEVICE, the packet will leave from {iface} regardless, "
            "but the next hop on that link must be reachable from this host."
        )

    # Optional sanity probe: does the kernel think a packet *forwarded* from
    # the spoofed source could reach this destination? A failure here is
    # informational, not a hard problem for the output path.
    if src_ip:
        _stdout, fwd_err, fwd_rc = _run(
            ["ip", "route", "get", dest_ip, "from", src_ip]
        )
        if fwd_rc is not None and fwd_rc != 0:
            report.add_info(
                f"`ip route get {dest_ip} from {src_ip}` failed "
                f"({fwd_err or 'no detail'}). This is expected for an off-net "
                "spoofed source and does not block the output path; it just "
                "means the kernel has no return route for that source IP."
            )


def _check_neighbour(dest_ip: str, iface: str, report: PreflightReport) -> None:
    """Confirm that a neighbour entry exists for the next hop."""
    # Find the gateway / next hop for the destination.
    route = _run_stdout(["ip", "route", "get", dest_ip]) or ""
    m = re.search(r"\bvia\s+(\S+)", route)
    next_hop = m.group(1) if m else dest_ip

    neigh = _run_stdout(["ip", "neigh", "show", next_hop, "dev", iface]) or ""
    if not neigh or "FAILED" in neigh.upper():
        report.add_warn(
            f"no neighbour entry for next-hop {next_hop} on {iface} "
            "(ARP/ND will be triggered on the first packet, which may be lost). "
            f"Pre-warm with: ping -c 1 -I {iface} {next_hop}"
        )
    else:
        report.add_info(f"neighbour: {neigh}")


def _check_firewall(report: PreflightReport) -> None:
    """Look for nftables/iptables rules that may drop locally generated traffic."""
    if shutil.which("nft"):
        out = _run_stdout(["nft", "list", "ruleset"]) or ""
        if re.search(r"chain\s+output", out, re.IGNORECASE) and \
           re.search(r"\b(drop|reject)\b", out):
            report.add_warn(
                "nftables OUTPUT chain contains drop/reject rules. "
                "Confirm they don't match your spoofed source/destination."
            )
    if shutil.which("iptables"):
        out = _run_stdout(["iptables", "-S", "OUTPUT"]) or ""
        non_default = [
            line for line in out.splitlines()
            if line and not line.startswith("-P ") and "ACCEPT" not in line
        ]
        if non_default:
            report.add_warn(
                "iptables OUTPUT has non-default rules; review with "
                "`sudo iptables -S OUTPUT`."
            )


def _check_l2_broadcast(dst_mac: str, routed: bool, report: PreflightReport) -> None:
    """Broadcast MAC + TCP is a common foot-gun for the L2 mode."""
    if routed:
        return
    if dst_mac.lower() in ("ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"):
        report.add_warn(
            "--dst-mac is broadcast. Most receivers ignore TCP frames whose "
            "destination MAC is the broadcast address (the kernel never hands "
            "them to a TCP socket). Use the receiver's actual MAC, e.g.\n"
            "        ip neigh show <receiver-ip>"
        )


def _check_receiver_hint(src_ip: Optional[str], report: PreflightReport) -> None:
    """A reminder about the most common cause: rp_filter on the receiver."""
    if not src_ip:
        return
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return
    test_nets = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    if any(addr in n for n in test_nets):
        report.add_info(
            f"--src-ip {src_ip} is in a TEST-NET range; the receiver almost "
            "certainly has no return route for it. If the receiver runs Linux "
            "with rp_filter=1 (the default on many distros) the packet will "
            "be silently dropped on arrival. On the *receiver* run:\n"
            "        sudo sysctl -w net.ipv4.conf.all.rp_filter=2\n"
            "        sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2\n"
            "        # or temporarily install a return route:\n"
            f"        sudo ip route add {addr.exploded}/32 dev <iface>"
        )


def _check_ip_forward(report: PreflightReport) -> None:
    val = _read_proc("/proc/sys/net/ipv4/ip_forward")
    if val is not None:
        report.add_info(f"ip_forward={val}")


def _check_root(report: PreflightReport) -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        report.add_warn(
            "preflight is running as a non-root user. Some checks "
            "(neighbour state, firewall) may be incomplete. Re-run with sudo "
            "for full visibility."
        )


def run_preflight(
    iface: str,
    dest_ip: str,
    src_ip: Optional[str] = None,
    routed: bool = False,
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
    quiet: bool = False,
) -> PreflightReport:
    """Run all diagnostics and return a populated report."""
    report = PreflightReport()
    _check_root(report)
    _check_interface(iface, report)
    if report.fatal:
        # No point continuing if the interface doesn't exist.
        if not quiet:
            report.print()
        return report

    _check_rp_filter(iface, report)
    _check_ip_forward(report)
    _check_local_source_ip(src_ip, iface, report)
    _check_destination_route(dest_ip, src_ip, iface, report)
    _check_neighbour(dest_ip, iface, report)
    _check_firewall(report)
    _check_l2_broadcast(dst_mac, routed, report)
    _check_receiver_hint(src_ip, report)

    if not quiet:
        report.print()
    return report


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pre-flight checks for spoofed TCP traffic.",
    )
    parser.add_argument("--iface", required=True, help="Egress interface")
    parser.add_argument("--dest-ip", required=True, help="Destination IPv4")
    parser.add_argument("--src-ip", default=None, help="Spoofed source IPv4")
    parser.add_argument("--routed", action="store_true",
                        help="Use kernel routing (no Ethernet frame crafting).")
    parser.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff",
                        help="Destination MAC for L2 mode (ignored with --routed).")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    report = run_preflight(
        iface=args.iface,
        dest_ip=args.dest_ip,
        src_ip=args.src_ip,
        routed=args.routed,
        dst_mac=args.dst_mac,
    )
    return 1 if report.fatal else 0


if __name__ == "__main__":
    raise SystemExit(main())
