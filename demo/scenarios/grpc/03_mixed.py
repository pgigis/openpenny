#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Scenario 3 — mixed: drive penny via gRPC instead of the CLI.

reeves1 generates both a legitimate iperf3 stream and a spoofed flow
toward reeves3 (see demo/scenarios/03-mixed.md). StartTest takes one
prefix at a time, so this script kicks off two runs back to back —
first for the legit aggregate, then for the spoofed aggregate.

Expected:
  - reeves1 -> reeves3        -> legitimate closed-loop
  - forged_src -> reeves3     -> not closed-loop
"""
import json

import grpc
import penny_pb2
import penny_pb2_grpc


REEVES1_PREFIX    = "10.0.0.1"        # set to reeves1's actual address
FORGED_SRC_PREFIX = "198.51.100.10"   # matches SPOOFED_SRC_IP default
MASK_BITS         = 32
IFACE             = "ens5f0np0"
QUEUE             = 0
QUEUE_COUNT       = 1

THRESHOLDS = {
    "packet_drop_probability":              0.05,
    "max_duplicate_ratio":                  0.15,
    "max_reordering_ratio":                 0.8,
    "retransmission_observation_miss_rate": 0.05,
    "retransmission_timeout_in_seconds":    3.0,
    "max_packet_drops_per_flow":            6,
    "max_packet_drops_global_aggregate":    12,
    "stop_after_individual_flows":          10,
}

PLATFORM = {
    "backend":     "af_xdp",
    "interface":   IFACE,
    "queue":       QUEUE,
    "queue_count": QUEUE_COUNT,
}


def run_one(stub, label, prefix):
    override = {
        "platform": PLATFORM,
        "runtime_policy": {
            "mode":       "active",
            "safety":     {"allow_ssh_bypass": True},
            "aggregates": {"enabled": True},
            "thresholds": THRESHOLDS,
        },
    }
    req = penny_pb2.StartTestRequest(
        prefix=prefix,
        mask_bits=MASK_BITS,
        mode="active",
        test_id=label,
        config_override_json=json.dumps(override),
    )
    resp = stub.StartTest(req)
    print(f"--- {label} ({prefix}/{MASK_BITS}) ---")
    print(f"status={resp.status}")
    print(f"aggregates_status={resp.aggregates_status}")
    print(f"aggregates_decision_complete={resp.aggregates_decision_complete}")
    print(f"aggregate_flows_closed_loop={resp.aggregate_flows_closed_loop}")
    print(f"aggregate_flows_not_closed_loop={resp.aggregate_flows_not_closed_loop}")


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub    = penny_pb2_grpc.PennyServiceStub(channel)

    run_one(stub, "mixed-legitimate", REEVES1_PREFIX)
    run_one(stub, "mixed-spoofed",    FORGED_SRC_PREFIX)


if __name__ == "__main__":
    main()
