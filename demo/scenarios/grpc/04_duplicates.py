#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Scenario 4 — duplicates: drive penny via gRPC instead of the CLI.

reeves1 injects a spoofed flow with a high duplicate probability
(see demo/scenarios/04-duplicates.md). This client tightens
max_duplicate_ratio so the aggregate exits via the duplicate path
rather than the closed-loop check.

Expected: aggregate forged_src -> reeves3 reaches "duplicate exceeded".
"""
import json

import grpc
import penny_pb2
import penny_pb2_grpc


IFACE       = "ens5f0np0"
QUEUE       = 0
QUEUE_COUNT = 1
DST_PORT    = 5201


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub    = penny_pb2_grpc.PennyServiceStub(channel)

    override = {
        "traffic_policy": {
            "default": "exclude",
            "rules": [{
                "name":     "iperf3-server",
                "decision": "include",
                "protocol": "tcp",
                "dst_port": DST_PORT,
            }],
        },
        "platform": {
            "backend":     "af_xdp",
            "interface":   IFACE,
            "queue":       QUEUE,
            "queue_count": QUEUE_COUNT,
        },
        "runtime_policy": {
            "mode": "active",
            "safety":     {"allow_ssh_bypass": True},
            "aggregates": {"enabled": True},
            "thresholds": {
                "packet_drop_probability":              0.05,
                # Tightened so the duplicate-heavy flow trips it quickly.
                "max_duplicate_ratio":                  0.10,
                "max_reordering_ratio":                 0.8,
                "retransmission_observation_miss_rate": 0.05,
                "retransmission_timeout_in_seconds":    3.0,
                "max_packet_drops_per_flow":            6,
                "max_packet_drops_global_aggregate":    12,
                "stop_after_individual_flows":          10,
            },
        },
    }

    req = penny_pb2.StartTestRequest(
        mode="active",
        test_id="duplicates",
        config_override_json=json.dumps(override),
    )

    resp = stub.StartTest(req)
    print(f"status={resp.status}")
    print(f"aggregates_status={resp.aggregates_status}")
    print(f"aggregates_decision_complete={resp.aggregates_decision_complete}")
    print(f"aggregate_flows_duplicates_exceeded={resp.aggregate_flows_duplicates_exceeded}")
    print(f"json_summary={resp.json_summary}")


if __name__ == "__main__":
    main()
