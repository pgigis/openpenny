#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""Simple TCP client that sends a message every second.

Usage:
    python client.py --host 127.0.0.1 --port 9000 [--message "hello"]

The client connects to the provided host/port and sends a message every second
until interrupted with Ctrl+C.
"""

import argparse
import socket
import sys
import time
from contextlib import closing

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP traffic generator")
    parser.add_argument("--host", required=True, help="Server IP address")
    parser.add_argument("--port", type=int, required=True, help="Server TCP port")
    parser.add_argument("--message", default="openpenny packet", help="Payload to send each second")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between packets (default: 1.0)")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    address = (args.host, args.port)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            sock.connect(address)
        except OSError as exc:
            print(f"[client] failed to connect to {args.host}:{args.port}: {exc}", file=sys.stderr)
            return 1

        print(f"[client] connected to {args.host}:{args.port}")
        message = args.message.encode()
        interval = max(args.interval, 0.1)

        try:
            while True:
                try:
                    sock.sendall(message + b"\n")
                    print(f"[client] sent: {args.message}")
                except OSError as exc:
                    print(f"[client] send failed: {exc}", file=sys.stderr)
                    return 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[client] stopping")
            return 0

if __name__ == "__main__":
    raise SystemExit(main())
