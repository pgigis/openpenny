#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Scenario 1 — legitimate: drive penny via gRPC instead of the CLI.

Equivalent to:
    sudo ./build/openpenny_cli \\
        -c examples/configs/config_default.yaml \\
        --source xdp --iface ens5f0np0 --queues 1

with reeves1 generating the 16-way iperf3 stream
(see demo/scenarios/01-legitimate.md).

The override JSON below is self-contained: it sets the traffic_policy,
platform, and runtime_policy in one StartTest call. The daemon's
on-disk YAML only supplies defaults that this override doesn't touch.

Expected: aggregate reeves1 -> reeves3 reaches "legitimate closed-loop".
"""
import json
import os
import re
import sys

import grpc
import penny_pb2
import penny_pb2_grpc


# Per-host knobs. Replaces the YAML's `CHANGE_ME` placeholder without
# hand-editing platform/af_xdp.yaml.
IFACE       = "ens5f0np0"
QUEUE       = 0
QUEUE_COUNT = 1
DST_PORT    = 5201          # iperf3 server port on reeves3


USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def color(value, code):
    if not USE_COLOR:
        return value
    return f"\033[{code}m{value}\033[0m"


def color_json(value):
    token_re = re.compile(
        r'("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?'
    )

    def replace(match):
        if match.group(1):
            return color(match.group(1), "36") + (match.group(2) or "") if match.group(2) else color(match.group(1), "32")
        if match.group(3):
            return color(match.group(3), "33")
        return color(match.group(0), "35")

    return token_re.sub(replace, value)


def format_json_summary(value):
    if not value:
        return "{}"
    try:
        return color_json(json.dumps(json.loads(value), indent=2, sort_keys=True))
    except json.JSONDecodeError:
        return value


def print_field(name, value, value_color=None):
    text = str(value)
    if value_color:
        text = color(text, value_color)
    print(f"{color(name, '1;34')}={text}")


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
                "max_duplicate_ratio":                  0.15,
                "max_reordering_ratio":                 0.8,
                "retransmission_observation_miss_rate": 0.05,
                "retransmission_timeout_in_seconds":    3.0,
                "max_packet_drops_per_flow":            6,
                "max_packet_drops_global_aggregate":    12,
                "stop_after_individual_flows":          3,
            },
        },
    }

    req = penny_pb2.StartTestRequest(
        mode="active",
        test_id="ripe92-demo",
        config_override_json=json.dumps(override),
    )

    resp = stub.StartTest(req)
    status_color = "32" if resp.status == "ok" else "31"
    print_field("status", resp.status, status_color)
    print_field("aggregates_status", resp.aggregates_status)
    print_field("aggregates_decision_complete", resp.aggregates_decision_complete)
    print_field("aggregate_flows_finished", resp.aggregate_flows_finished)
    print_field("aggregate_flows_closed_loop", resp.aggregate_flows_closed_loop)
    print(color("json_summary:", "1;34"))
    print(format_json_summary(resp.json_summary))


if __name__ == "__main__":
    main()
