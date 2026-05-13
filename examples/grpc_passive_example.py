#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""
Minimal gRPC client calling StartTest in passive mode with an inline JSON config override.
"""
import json
import grpc
import penny_pb2
import penny_pb2_grpc


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub = penny_pb2_grpc.PennyServiceStub(channel)

    override = {
        "runtime_policy": {
            "mode": "passive",
            "aggregates": {"enabled": False},
            "safety": {"allow_ssh_bypass": True},
            "thresholds": {
                "passive_min_flows_to_finish": 10,
                "passive_max_parallel_flows": 10,
                "passive_max_execution_time_seconds": 150,
                "monitored_flow_idle_expiry_seconds": 15.0,
            },
        }
    }

    req = penny_pb2.StartTestRequest(
        prefix="192.168.41.1",
        mask_bits=32,
        mode="passive",
        test_id="grpc-passive-demo",
        config_override_json=json.dumps(override),
    )

    resp = stub.StartTest(req)
    print(f"status={resp.status}")
    print(f"packets_processed={resp.packets_processed}")
    print(f"json_summary={resp.json_summary}")


if __name__ == "__main__":
    main()
