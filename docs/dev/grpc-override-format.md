# gRPC Config Override Format (JSON)

`StartTestRequest.config_override_json` lets a single `StartTest` call
override parts of the on-disk YAML. Anything omitted falls back to the
loaded config.

For changes that should persist across calls, use the typed RPCs —
`ApplyConfig`, `SetTrafficPolicy`, `SetRuntimePolicy`, `SetMode`.
`config_override_json` is for per-run tweaks.

Accepted top-level keys: `traffic_policy`, `runtime_policy`, `platform`,
`egress`, `log`. The legacy `monitoring.*` / `input_sources.*` /
`traffic_forwarding.*` shapes have been retired.

## Runtime policy (active)

```json
{
  "runtime_policy": {
    "mode": "active",
    "safety": { "allow_ssh_bypass": true },
    "aggregates": { "enabled": true },
    "thresholds": {
      "packet_drop_probability": 0.05,
      "max_duplicate_ratio": 0.15,
      "max_reordering_ratio": 0.8,
      "retransmission_observation_miss_rate": 0.05,
      "retransmission_timeout_in_seconds": 3.0,
      "max_packet_drops_per_flow": 6,
      "max_packet_drops_global_aggregate": 12,
      "stop_after_individual_flows": 10
    }
  }
}
```

## Runtime policy (passive)

```json
{
  "runtime_policy": {
    "mode": "passive",
    "aggregates": { "enabled": false },
    "thresholds": {
      "passive_min_flows_to_finish": 5,
      "passive_max_parallel_flows": 5,
      "passive_max_execution_time_seconds": 20,
      "monitored_flow_idle_expiry_seconds": 30
    }
  }
}
```

## Traffic policy

```json
{
  "traffic_policy": {
    "default": "exclude",
    "rules": [
      {
        "name": "https",
        "priority": 10,
        "decision": "include",
        "protocol": "tcp",
        "dst_prefix": "203.0.113.0/24",
        "dst_port": 443
      }
    ]
  }
}
```

## Platform

```json
{
  "platform": {
    "backend": "af_xdp",
    "ingress_mode": "auto",
    "interface": "ens5f0np0",
    "queue": 0,
    "queue_count": 1
  }
}
```

## Egress

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

## Shorthand request fields

`StartTestRequest` carries a handful of legacy shorthand fields that map
into the typed blocks above; they are kept for backward compatibility
and should not be used by new clients.

| Request field      | Maps to                              |
| ------------------ | ------------------------------------ |
| `prefix`, `mask_bits` | synthesised `traffic_policy.rules[0].dst_prefix` (when no `traffic_policy` override is set) |
| `forward_to_tun`   | `egress.kind` = `tun` or `none`      |
| `tun_name`         | `egress.device`                      |
| `tun_multi_queue`  | `egress.tun.multi_queue`             |
| `tun_mtu`          | `egress.tun.mtu`                     |
| `forward_raw_socket` / `forward_device` | `egress.kind` = `raw_socket`, `egress.device` |

## Notes

- The server writes the merged JSON to a temporary YAML file and points
  the worker at it. JSON is a YAML subset, so this round-trips.
- Only the keys you set are overridden; everything else is read from
  the on-disk config.
