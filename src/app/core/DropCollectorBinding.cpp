// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/DropCollectorBinding.h"

#include "openpenny/app/core/PerThreadStats.h"

#include <algorithm>

namespace openpenny::app {
namespace {

DropCollector::TimestampRep snapshot_timestamp(
    const penny::PacketDropSnapshot& snap) noexcept {
    return snap.timestamp.time_since_epoch().count();
}

bool is_pending_snapshot(const penny::PacketDropSnapshot& snap) noexcept {
    return snap.state == penny::SnapshotState::Pending;
}

bool try_reserve_snapshot_slot(DropCollector& collector) noexcept {
    if (collector.snapshot_limit == 0) {
        return true;
    }
    auto reserved = collector.accepted_snapshot_count.load(std::memory_order_relaxed);
    while (reserved < collector.snapshot_limit) {
        if (collector.accepted_snapshot_count.compare_exchange_weak(
                reserved,
                reserved + 1,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

void maybe_freeze_aggregate_window(DropCollector& collector,
                                   const openpenny::app::AggregatedCounters& agg) {
    if (collector.snapshot_limit == 0 ||
        collector.accepted_snapshot_count.load(std::memory_order_relaxed) < collector.snapshot_limit) {
        return;
    }
    std::lock_guard<std::mutex> lock(collector.frozen_aggregate_counters_mtx);
    if (!collector.frozen_aggregate_counters) {
        collector.frozen_aggregate_counters = agg;
    }
}

void apply_frozen_aggregate_transition(DropCollector& collector,
                                       const penny::PacketDropSnapshot& before,
                                       const penny::PacketDropSnapshot& after) {
    if (before.state == after.state) {
        return;
    }
    std::lock_guard<std::mutex> lock(collector.frozen_aggregate_counters_mtx);
    if (!collector.frozen_aggregate_counters) {
        return;
    }
    auto& agg = *collector.frozen_aggregate_counters;
    if (before.state == penny::SnapshotState::Pending &&
        agg.pending_retransmissions > 0) {
        --agg.pending_retransmissions;
    }
    if (after.state == penny::SnapshotState::Retransmitted) {
        ++agg.retransmitted_packets;
    } else if (after.state == penny::SnapshotState::Expired) {
        ++agg.non_retransmitted_packets;
    }
}

} // namespace

DropCollectorBinding& DropCollectorBinding::instance() {
    static DropCollectorBinding inst;
    return inst;
}

void DropCollectorBinding::upsert(DropCollectorPtr collector,
                                  const std::string& thread_name,
                                  std::size_t shard_index,
                                  const FlowKey& key,
                                  penny::PacketDropId packet_id,
                                  const penny::PacketDropSnapshot& snap) {
    if (!collector) return;
    if (!collector->accepting.load(std::memory_order_relaxed)) return;
    auto& shard = collector->shard_for(shard_index);
    std::lock_guard<std::mutex> lock(shard.mtx);
    if (!collector->accepting.load(std::memory_order_relaxed)) return;
    upsert_locked(*collector, shard, thread_name, key, packet_id, snap);
}

void DropCollectorBinding::refresh_from(
    DropCollectorPtr collector,
    const std::string& thread_name,
    std::size_t shard_index,
    const FlowKey& key,
    const std::vector<std::pair<penny::PacketDropId, penny::PacketDropSnapshot>>& snapshots,
    std::size_t start_index) {
    if (!collector) return;
    if (!collector->accepting.load(std::memory_order_relaxed)) return;
    if (start_index >= snapshots.size()) return;

    auto& shard = collector->shard_for(shard_index);
    std::lock_guard<std::mutex> lock(shard.mtx);
    if (!collector->accepting.load(std::memory_order_relaxed)) return;

    for (std::size_t i = start_index; i < snapshots.size(); ++i) {
        const auto& pair = snapshots[i];
        upsert_locked(*collector, shard, thread_name, key, pair.first, pair.second);
    }
}

void DropCollectorBinding::upsert_locked(DropCollector& collector,
                                         DropCollector::Shard& shard,
                                         const std::string& thread_name,
                                         const FlowKey& key,
                                         penny::PacketDropId packet_id,
                                         const penny::PacketDropSnapshot& snap) {
    auto& snapshots = shard.snapshots;
    DropCollector::SnapshotKey snapshot_key{key, packet_id};

    auto index_it = shard.snapshot_index.find(snapshot_key);
    if (index_it != shard.snapshot_index.end()) {
        auto& rec = snapshots[index_it->second];
        const auto previous_snapshot = rec.snapshot;
        auto pending_count = shard.pending_snapshot_count.load(std::memory_order_relaxed);
        const bool was_pending = is_pending_snapshot(rec.snapshot);
        const bool now_pending = is_pending_snapshot(snap);
        rec.snapshot = snap;
        if (was_pending != now_pending) {
            if (now_pending) {
                ++pending_count;
            } else if (pending_count > 0) {
                --pending_count;
            }
            shard.pending_snapshot_count.store(pending_count, std::memory_order_relaxed);
        }
        apply_frozen_aggregate_transition(collector, previous_snapshot, snap);
    } else {
        if (!try_reserve_snapshot_slot(collector)) {
            return;
        }
        const auto agg_now = openpenny::app::aggregate_counters();
        const auto idx = snapshots.size();
        snapshots.push_back(DropSnapshotRecord{key, packet_id, snap, agg_now, thread_name});
        shard.snapshot_index.emplace(std::move(snapshot_key), idx);
        shard.snapshot_count.store(snapshots.size(), std::memory_order_relaxed);
        if (is_pending_snapshot(snap)) {
            const auto pending_count =
                shard.pending_snapshot_count.load(std::memory_order_relaxed);
            shard.pending_snapshot_count.store(pending_count + 1, std::memory_order_relaxed);
        }
        const auto ts = snapshot_timestamp(snap);
        const auto latest_ts =
            shard.latest_snapshot_timestamp.load(std::memory_order_relaxed);
        if (ts >= latest_ts) {
            shard.latest_snapshot_index.store(idx, std::memory_order_relaxed);
            shard.latest_snapshot_timestamp.store(ts, std::memory_order_relaxed);
        }
        maybe_freeze_aggregate_window(collector, agg_now);
    }
}

} // namespace openpenny::app
