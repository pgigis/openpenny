# gRPC Client Example (Python)

How to call `StartTest` from Python with an inline JSON config override and read the returned summary. Assumes Python stubs (`penny_pb2.py`, `penny_pb2_grpc.py`) generated from `proto/penny.proto`.

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
}
```

### Passive Response Example

`individual_flows` always carries the three categorised buckets
(`closed_loop`, `not_closed_loop`, `duplicates_exceeded`), each with a
`count` and a `flows[]` array. Buckets that didn't accumulate anything
just have empty arrays.

```json
{
  "test": {
    "id": "demo-client",
    "status": "ok",
    "end_state": "Passive pipeline completed (flows=10)",
    "penny_completed": true,
    "aggregates": {
      "enabled": false,
      "completed": false,
      "status": "n/a",
      "decision_complete": false,
      "decision_state": "n/a",
      "has_eval": false,
      "snapshots": 0,
      "eval": {
        "data": 0,
        "duplicate": 0,
        "retransmitted": 0,
        "non_retransmitted": 0
      },
      "flows": {
        "monitored": 0,
        "finished": 0,
        "closed_loop": 0,
        "not_closed_loop": 0,
        "rst": 0,
        "duplicates_exceeded": 0
      }
    },
    "individual_flows": {
      "tracked_syn": 0,
      "tracked_data": 10,
      "closed_loop": {
        "count": 0,
        "flows": []
      },
      "not_closed_loop": {
        "count": 0,
        "flows": []
      },
      "duplicates_exceeded": {
        "count": 0,
        "flows": []
      }
    },
    "overall": {
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
      }
    },
    "passive": {
      "finished": 10,
      "open_gaps_flows": 0,
      "open_gaps": 0,
      "rst": 0,
      "syn_only": 0,
      "details": []
    }
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
    "runtime_policy": {
      "mode": "active",
      "aggregates": {"enabled": true},
      "thresholds": {
        "packet_drop_probability": 0.05,
        "max_duplicate_ratio": 0.15,
        "retransmission_timeout_in_seconds": 3.0,
        "admission_grace_period_seconds": 3.0,
        "monitored_flow_idle_expiry_seconds": 30.0
      }
    }
  }
}
```

### Active Response Example

Aggregates reached a decision (`closed_loop`), but `individual_flows`
still lists the categorised per-flow stats — the aggregate verdict is
grounded in those buckets, so they're informative even when the
aggregate phase has stopped the test.

```json
{
  "test": {
    "id": "active-demo",
    "status": "ok",
    "end_state": "Aggregates completed (closed_loop), found 8 closed-loop flows",
    "penny_completed": true,
    "aggregates": {
      "enabled": true,
      "completed": true,
      "status": "closed_loop",
      "decision_complete": true,
      "decision_state": "completed",
      "has_eval": true,
      "snapshots": 3,
      "eval": {
        "data": 44930,
        "duplicate": 120,
        "retransmitted": 15,
        "non_retransmitted": 3
      },
      "flows": {
        "monitored": 10,
        "finished": 10,
        "closed_loop": 8,
        "not_closed_loop": 2,
        "rst": 0,
        "duplicates_exceeded": 0
      }
    },
    "individual_flows": {
      "tracked_syn": 10,
      "tracked_data": 10,
      "closed_loop": {
        "count": 8,
        "flows": [
          "10.0.0.1:5000 -> 10.0.0.2:80 data=5612 dropped=0 rtx=2 non_rtx=5610 dup=15 in_order=5587 out_of_order=25",
          "...7 more..."
        ]
      },
      "not_closed_loop": {
        "count": 2,
        "flows": [
          "10.0.0.1:5100 -> 10.0.0.2:80 data=10 dropped=0 rtx=0 non_rtx=10 dup=0 in_order=10 out_of_order=0",
          "10.0.0.1:5101 -> 10.0.0.2:80 data=8 dropped=0 rtx=0 non_rtx=8 dup=0 in_order=8 out_of_order=0"
        ]
      },
      "duplicates_exceeded": {
        "count": 0,
        "flows": []
      }
    },
    "overall": {
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
      }
    }
  }
}
```
