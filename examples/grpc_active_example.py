#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""
Minimal gRPC client calling StartTest in active mode with an inline JSON config override.
"""
import json
import grpc
import penny_pb2
import penny_pb2_grpc


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub = penny_pb2_grpc.PennyServiceStub(channel)

    override = {
        "monitoring": {
            "active": {
                "enabled": True,
                "aggregates": {
                    "enabled": True,
                    "max_monitored_flows": 100,
                    "fallback_to_individual": True,
                    "min_individual_flows_for_closed_loop": 2,
                },
                "drop_policy": {
                    "packet_drop_probability": 0.05,
                    "max_duplicate_ratio": 0.15,
                    "max_reordering_ratio": 0.8,
                    "retransmission_observation_miss_rate": 0.05,
                },
                "timeouts": {
                    "retransmission_timeout_seconds": 3.0,
                    "admission_grace_period_seconds": 3.0,
                    "monitored_flow_idle_expiry_seconds": 30.0,
                },
                "execution": {
                    "max_packet_drops_per_flow": 6,
                    "max_packet_drops_global_aggregate": 12,
                    "stop_after_individual_flows": 10,
                },
            },
            "passive": {"enabled": False, "aggregates": {"enabled": False}}
        }
    }

    req = penny_pb2.StartTestRequest(
        prefix="192.168.41.1",
        mask_bits=32,
        mode="active",
        test_id="grpc-active-demo",
        config_override_json=json.dumps(override),
    )

    resp = stub.StartTest(req)
    print(f"status={resp.status}")
    print(f"packets_processed={resp.packets_processed}")
    print(f"json_summary={resp.json_summary}")


if __name__ == "__main__":
    main()
