#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Scenario 3 — mixed: drive penny via gRPC instead of the CLI.

reeves1 generates both a legitimate iperf3 stream and a spoofed flow
toward reeves3 (see demo/scenarios/03-mixed.md). Penny watches the
TCP dst_port 5201 rule from the config and tracks the two
aggregates (reeves1 -> reeves3, forged_src -> reeves3) concurrently
in one run.

Expected on the response:
  - aggregate_flows_closed_loop      > 0   (the legit aggregate)
  - aggregate_flows_not_closed_loop  > 0   (the spoofed aggregate)
"""
import json

import grpc
import penny_pb2
import penny_pb2_grpc


IFACE       = "ens5f0np0"
QUEUE       = 0
QUEUE_COUNT = 1


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub    = penny_pb2_grpc.PennyServiceStub(channel)

    override = {
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
                "max_duplicate_ratio":                  0.15,
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
        test_id="mixed",
        config_override_json=json.dumps(override),
    )

    resp = stub.StartTest(req)
    print(f"status={resp.status}")
    print(f"aggregates_status={resp.aggregates_status}")
    print(f"aggregates_decision_complete={resp.aggregates_decision_complete}")
    print(f"aggregate_flows_closed_loop={resp.aggregate_flows_closed_loop}")
    print(f"aggregate_flows_not_closed_loop={resp.aggregate_flows_not_closed_loop}")
    print(f"json_summary={resp.json_summary}")


if __name__ == "__main__":
    main()
