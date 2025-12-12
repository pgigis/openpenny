# gRPC Config Override Format (JSON)

`StartTestRequest.config_override_json` accepts an inline JSON object that replaces the on-disk YAML for that call. Provide the full `monitoring` block(s) you want applied. Keys mirror the YAML.

## Passive override example
```json
{
  "monitoring": {
    "passive": {
      "enabled": true,
      "min_number_of_flows_to_finish": 5,
      "max_execution_time": 20,
      "max_parallel_flows": 5,
      "timeouts": {
        "monitored_flow_idle_expiry_seconds": 30
      }
    }
  }
}
```

## Active override example
```json
{
  "monitoring": {
    "active": {
      "enabled": true,
      "drop_policy": {
        "packet_drop_probability": 0.05,
        "max_duplicate_ratio": 0.15,
        "max_reordering_ratio": 0.8
      },
      "timeouts": {
        "retransmission_timeout_seconds": 3.0,
        "admission_grace_period_seconds": 3.0,
        "monitored_flow_idle_expiry_seconds": 30.0
      },
      "execution": {
        "max_packet_drops_per_flow": 6,
        "max_packet_drops_global_aggregate": 12,
        "stop_after_individual_flows": 10
      }
    }
  }
}
```

## Notes
- Only fields provided are overridden; anything omitted falls back to the on-disk config or defaults.
- The server writes this JSON to a temp file and points the worker at it.
- Remember to regenerate protobuf/gRPC stubs after the `config_override_json` field change.
