#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""Simple TCP server that prints any data it receives.

Usage:
    python server.py --host 0.0.0.0 --port 9000

The server listens on the provided host/port, accepts one connection at a time,
prints every line of data it receives, and keeps running until interrupted.
"""

import argparse
import socket
import sys
from contextlib import closing


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP server for packet capture demos")
    parser.add_argument("--host", default="0.0.0.0", help="IP address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, required=True, help="TCP port to listen on")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    address = (args.host, args.port)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(address)
        server.listen(1)
        print(f"[server] listening on {args.host}:{args.port}")

        try:
            while True:
                conn, peer = server.accept()
                with closing(conn):
                    print(f"[server] connection from {peer[0]}:{peer[1]}")
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            print("[server] client disconnected")
                            break
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n[server] shutting down")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
