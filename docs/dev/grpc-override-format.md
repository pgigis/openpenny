# gRPC Config Override Format (JSON)

`StartTestRequest.config_override_json` lets a single `StartTest` call
override parts of the on-disk YAML. Anything omitted falls back to the
loaded config.

The high-level RPCs (`ApplyConfig`, `SetTrafficPolicy`, `SetRuntimePolicy`,
`SetMode`) take typed policy objects and are the right choice when you
want changes to persist across calls. Use `config_override_json` when you
want a tweak that applies to one run only.

## Runtime policy override (active)

```json
{
  "runtime_policy": {
    "mode": "active",
    "thresholds": {
      "packet_drop_probability": 0.05,
      "max_duplicate_ratio": 0.15,
      "max_reordering_ratio": 0.8,
      "retransmission_observation_miss_rate": 0.05,
      "retransmission_timeout_multiplier": 3.0,
      "max_packet_drops_per_flow": 6,
      "max_packet_drops_global_aggregate": 12
    },
    "safety": {
      "allow_ssh_bypass": true
    }
  }
}
```

## Runtime policy override (passive)

```json
{
  "runtime_policy": {
    "mode": "passive",
    "thresholds": {
      "passive_min_flows_to_finish": 5,
      "passive_max_parallel_flows": 5,
      "passive_max_execution_time_seconds": 20,
      "monitored_flow_idle_expiry_seconds": 30
    }
  }
}
```

## Egress override

```json
{
  "egress": {
    "kind": "tun",
    "device": "xdp-tun",
    "tun": { "multi_queue": true, "mtu": 9000 }
  }
}
```

Use `"kind": "none"` to disable forwarding. `raw_socket` and `raw_nic`
are also accepted; see
[`docs/run/configuration-examples.md`](../run/configuration-examples.md)
for the full YAML shape.

## Notes

- The server writes this JSON to a temp file and points the worker at it.
- Only the fields you set are overridden; everything else is read from
  the on-disk config.
