# gRPC Client Example (Python)

This example demonstrates how to invoke `StartTest` from Python using an inline JSON configuration override, and how to parse the returned JSON summary. It assumes Python stubs (`penny_pb2.py`, `penny_pb2_grpc.py`) were generated from `proto/penny.proto`.

## Minimal Python Client

```python
import grpc
import penny_pb2
import penny_pb2_grpc
import json

def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub = penny_pb2_grpc.PennyServiceStub(channel)

    override_json = {
        "monitoring": {
            "active": {
                "enabled": True,
                "aggregates": {
                    "enabled": True,
                    "max_monitored_flows": 100,
                    "fallback_to_individual": True,
                    "min_individual_flows_for_closed_loop": 2
                },
                "drop_policy": {
                    "packet_drop_probability": 0.05,
                    "max_duplicate_ratio": 0.15,
                    "max_reordering_ratio": 0.8,
                    "retransmission_observation_miss_rate": 0.05
                },
                "timeouts": {
                    "retransmission_timeout_seconds": 3.0,
                    "admission_grace_period_seconds": 3.0,
                    "monitored_flow_idle_expiry_seconds": 30.0
                },
                "execution": {
                    "max_packet_drops_per_flow": 6,
                    "max_packet_drops_global_aggregate": 12,
                    "max_number_of_individual_flows": 10,
                    "stop_after_individual_flows": 10
                }
            },
            "passive": {
                "enabled": True,
                "aggregates": {"enabled": False},
                "min_number_of_flows_to_finish": 10,
                "max_parallel_flows": 10,
                "max_execution_time": 150,
                "timeouts": {
                    "admission_grace_period_seconds": 3.0,
                    "monitored_flow_idle_expiry_seconds": 15.0
                }
            }
        }
    }

    req = penny_pb2.StartTestRequest(
        prefix="192.168.41.1",
        mask_bits=32,
        mode="passive",
        test_id="demo-client",
        config_override_json=json.dumps(override_json),
    )

    resp = stub.StartTest(req)
    print("Status:", resp.status)
    print("Packets processed:", resp.packets_processed)
    print("JSON summary:", resp.json_summary)  # CLI-like JSON detail

if __name__ == "__main__":
    main()
```

### Notes

- Update `localhost:50051` if your server listens elsewhere.
- Ensure protobuf stubs are generated from `proto/penny.proto`.
- `config_override_json` overrides the entire worker config for that run.

## Example Calls and Responses

### Passive Request Example

```json
{
  "prefix": "192.168.41.1",
  "mask_bits": 32,
  "mode": "passive",
  "test_id": "demo-client",
  "config_override_json": {
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
}
```

### Passive Response Example

```json
{
  "test_id": "demo-client",
  "status": "ok",
  "packets": {
    "processed": 7288,
    "forwarded": 7288,
    "errors": 0,
    "pure_ack": 0,
    "data": 14,
    "duplicate": 0,
    "in_order": 14,
    "out_of_order": 0,
    "retransmitted": 0,
    "non_retransmitted": 0
  },
  "flows": {
    "tracked_syn": 0,
    "tracked_data": 10,
    "details": [
      {
        "key": "{192.168.41.1-192.168.41.2-54564-5201}",
        "start": "syn",
        "end": "fin",
        "data": 10,
        "pure_ack": 2,
        "dup": 0,
        "in_order": 12,
        "out_of_order": 0,
        "rst": 0,
        "syn": 1,
        "gaps_open": 0,
        "gaps": []
      }
    ]
  },
  "penny_completed": true,
  "aggregates_completed": false,
  "aggregates_enabled": false,
  "aggregates_status": "n/a",
  "aggregates_decision_complete": false,
  "aggregates_decision_state": "n/a",
  "aggregates_has_eval": false,
  "aggregates_snapshots": 0,
  "aggregates_eval": {
    "data": 0,
    "duplicate": 0,
    "retransmitted": 0,
    "non_retransmitted": 0
  },
  "aggregate_flows": {
    "monitored": 0,
    "finished": 0,
    "closed_loop": 0,
    "not_closed_loop": 0,
    "rst": 0,
    "duplicates_exceeded": 0
  }
}
```

### Active Request Example

```json
{
  "prefix": "192.168.50.0",
  "mask_bits": 24,
  "mode": "active",
  "test_id": "active-demo",
  "config_override_json": {
    "monitoring": {
      "active": {
        "enabled": true,
        "drop_policy": {
          "packet_drop_probability": 0.05,
          "max_duplicate_ratio": 0.15
        },
        "timeouts": {
          "retransmission_timeout_seconds": 3.0,
          "admission_grace_period_seconds": 3.0,
          "monitored_flow_idle_expiry_seconds": 30.0
        }
      }
    }
  }
}
```

### Active Response Example

```json
{
  "test_id": "active-demo",
  "status": "ok",
  "packets": {
    "processed": 45000,
    "forwarded": 44980,
    "errors": 0,
    "pure_ack": 50,
    "data": 44930,
    "duplicate": 120,
    "in_order": 44700,
    "out_of_order": 230,
    "retransmitted": 15,
    "non_retransmitted": 3
  },
  "flows": {
    "tracked_syn": 5,
    "tracked_data": 12
  },
  "penny_completed": true,
  "aggregates_completed": true,
  "aggregates_enabled": true,
  "aggregates_status": "closed_loop",
  "aggregates_decision_complete": true,
  "aggregates_decision_state": "completed",
  "aggregates_has_eval": true,
  "aggregates_snapshots": 3,
  "aggregates_eval": {
    "data": 44930,
    "duplicate": 120,
    "retransmitted": 15,
    "non_retransmitted": 3
  },
  "aggregate_flows": {
    "monitored": 10,
    "finished": 10,
    "closed_loop": 8,
    "not_closed_loop": 2,
    "rst": 0,
    "duplicates_exceeded": 0
  }
}
```
