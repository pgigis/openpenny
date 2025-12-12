#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""
Helpers for building and attaching the lab XDP program.

This module mirrors the helper logic used by `traffic_generator/server.py`
so other tooling in the repo can ensure the `xdp-fw/xdp_redirect_dstprefix.c`
program is present and attached.

It can also be executed directly:

    python3 scripts/xdp_attach.py --iface ens5f0np0 --mode auto
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence


def run_cmd(
    cmd: Sequence[str],
    *,
    sudo: bool = False,
    capture_output: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command, optionally via sudo."""
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=True,
    )


def build_xdp_program(xdp_dir: Path) -> Path:
    """Ensure the XDP object is built and return its path."""
    obj = xdp_dir / "xdp_redirect_dstprefix.o"
    if obj.exists():
        return obj
    run_cmd(["make", "-C", str(xdp_dir), "xdp_redirect_dstprefix.o"])
    if not obj.exists():
        raise FileNotFoundError(f"Failed to build {obj}")
    return obj


def xdp_already_attached(iface: str) -> bool:
    """Return True if an XDP program already appears attached to iface."""
    try:
        result = run_cmd(
            ["ip", "-details", "link", "show", "dev", iface],
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return False
    output = result.stdout or ""
    return "prog/xdp" in output or "xdpgeneric" in output


def attach_xdp_program(iface: str, mode: str, obj_path: Path) -> bool:
    """Attach the XDP program to iface using the requested mode."""
    if os.geteuid() != 0:
        print(
            "[xdp] attaching requires root privileges. "
            "Re-run with sudo or as root.",
            file=sys.stderr,
        )
        return False

    mode_order = {
        "drv": ["xdpdrv"],
        "generic": ["xdpgeneric"],
        "auto": ["xdpdrv", "xdpgeneric"],
    }[mode]

    for attach_mode in mode_order:
        cmd = [
            "ip",
            "link",
            "set",
            "dev",
            iface,
            attach_mode,
            "obj",
            str(obj_path),
            "sec",
            "xdp",
        ]
        try:
            run_cmd(cmd, sudo=True)
            print(f"[xdp] attached {obj_path.name} to {iface} via {attach_mode}")
            return True
        except subprocess.CalledProcessError as exc:
            print(f"[xdp] attach via {attach_mode} failed: {exc}", file=sys.stderr)
    return False


def ensure_xdp_attached(iface: str, mode: str = "auto") -> bool:
    """
    Ensure the lab XDP program is attached to *iface*.

    Returns True if the program is present/attached, False on failure.
    """
    project_root = Path(__file__).resolve().parent
    xdp_dir = project_root / "xdp-fw"
    if not xdp_dir.is_dir():
        print("[xdp] could not locate xdp-fw; ensure it exists", file=sys.stderr)
        return False

    try:
        obj_path = build_xdp_program(xdp_dir)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"[xdp] failed to build XDP program: {exc}", file=sys.stderr)
        return False

    if xdp_already_attached(iface):
        print(f"[xdp] XDP program already attached to {iface}")
        return True

    return attach_xdp_program(iface, mode, obj_path)


def detach_xdp_program(iface: str) -> bool:
    """Detach any XDP program from iface."""
    try:
        run_cmd(["ip", "link", "set", "dev", iface, "xdp", "off"], sudo=True)
        print(f"[xdp] detached XDP program from {iface}")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"[xdp] failed to detach XDP program from {iface}: {exc}", file=sys.stderr)
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage the lab XDP attachment",
    )
    parser.add_argument("--iface", required=True, help="Interface to target")
    parser.add_argument(
        "--mode",
        choices=["auto", "drv", "generic"],
        default="auto",
        help="Attachment mode (default: auto)",
    )
    parser.add_argument(
        "--detach",
        action="store_true",
        help="Detach the XDP program instead of attaching",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.detach:
        ok = detach_xdp_program(args.iface)
    else:
        ok = ensure_xdp_attached(args.iface, args.mode)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
