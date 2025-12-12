#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""
Simple gRPC client for the Penny daemon.

Usage:
    python3 grpc_client.py --addr localhost:50051 --prefix 10.0.0.0 --mask-bits 24 --test-id demo

Behavior:
  - Connects to the Penny gRPC server.
  - Sends a StartTest request with the provided prefix/mask (YAML defaults apply for the rest).
  - Blocks until the test completes and prints the returned counters.

Requires: grpcio; grpcio-tools if stubs are not pre-generated (the script will generate them to a temp dir).
"""

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Tuple

import grpc


def ensure_stubs() -> Tuple[object, object]:
    """Import or generate penny_pb2 / penny_pb2_grpc and return the modules."""
    try:
        import penny_pb2  # type: ignore
        import penny_pb2_grpc  # type: ignore
        return penny_pb2, penny_pb2_grpc
    except ModuleNotFoundError:
        pass

    repo_root = Path(__file__).resolve().parent.parent
    proto_path = repo_root / "proto"
    proto_file = proto_path / "penny.proto"
    if not proto_file.is_file():
        print(f"[grpc-client] proto file not found at {proto_file}", file=sys.stderr)
        sys.exit(1)

    try:
        from grpc_tools import protoc  # type: ignore
    except ModuleNotFoundError:
        print("[grpc-client] grpcio-tools not installed; install with `pip install grpcio-tools`", file=sys.stderr)
        sys.exit(1)

    temp_dir = Path(tempfile.mkdtemp(prefix="penny_grpc_"))
    args = [
        "protoc",
        f"-I{proto_path}",
        f"--python_out={temp_dir}",
        f"--grpc_python_out={temp_dir}",
        str(proto_file),
    ]
    if protoc.main(args) != 0:
        print("[grpc-client] protoc generation failed", file=sys.stderr)
        sys.exit(1)
    sys.path.insert(0, str(temp_dir))
    import penny_pb2  # type: ignore # noqa: E402
    import penny_pb2_grpc  # type: ignore # noqa: E402
    return penny_pb2, penny_pb2_grpc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Penny gRPC client for StartTest")
    parser.add_argument("--addr", default="127.0.0.1:50051", help="pennyd address (host:port)")
    parser.add_argument("--prefix", required=True, help="Prefix IP (e.g., 10.0.0.0)")
    parser.add_argument("--mask-bits", type=int, required=True, help="Prefix mask bits (e.g., 24)")
    parser.add_argument("--test-id", default="cli", help="Optional test id for correlation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pb2, pb2_grpc = ensure_stubs()

    req = pb2.StartTestRequest(prefix=args.prefix, mask_bits=args.mask_bits, test_id=args.test_id)
    with grpc.insecure_channel(args.addr) as channel:
        stub = pb2_grpc.PennyServiceStub(channel)
        try:
            resp = stub.StartTest(req)
        except grpc.RpcError as exc:
            print(f"[grpc-client] RPC failed: {exc}", file=sys.stderr)
            return 1

    if resp.status != "ok":
        print(f"[grpc-client] server reported error: {resp.status}", file=sys.stderr)
        return 1

    print(f"[grpc-client] test_id={resp.test_id} status={resp.status}")
    print(f"  packets_processed:    {resp.packets_processed}")
    print(f"  packets_forwarded:    {resp.packets_forwarded}")
    print(f"  forward_errors:       {resp.forward_errors}")
    print(f"  pure_ack_packets:     {resp.pure_ack_packets}")
    print(f"  data_packets:         {resp.data_packets}")
    print(f"  duplicate_packets:    {resp.duplicate_packets}")
    print(f"  in_order_packets:     {resp.in_order_packets}")
    print(f"  out_of_order_packets: {resp.out_of_order_packets}")
    print(f"  retransmitted_packets:{resp.retransmitted_packets}")
    print(f"  non_retransmitted_packets: {resp.non_retransmitted_packets}")
    print(f"  pending_retransmissions:   {resp.pending_retransmissions}")
    print(f"  penny_completed:      {resp.penny_completed}")
    print(f"  aggregates_penny_completed: {resp.aggregates_penny_completed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
