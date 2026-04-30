// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/DropCollectorBinding.h"

#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <algorithm>
#include <utility>

namespace openpenny::app {
namespace {

DropCollector::TimestampRep snapshot_timestamp(
    const penny::PacketDropSnapshot& snap) noexcept {
    return snap.timestamp.time_since_epoch().count();
}

bool is_pending_snapshot(const penny::PacketDropSnapshot& snap) noexcept {
    return snap.state == penny::SnapshotState::Pending;
}

} // namespace

DropCollectorBinding& DropCollectorBinding::instance() {
    static DropCollectorBinding inst;
    return inst;
}

void DropCollectorBinding::ensure_snapshot_hook() {
    std::call_once(hook_once_, []() {
        penny::ThreadFlowEventTimerManager::set_snapshot_hook(
            [](penny::FlowEngine* flow,
               penny::PacketDropId packet_id,
               penny::ThreadFlowEventTimerManager::SnapshotEventKind /*kind*/) {
                auto& self = DropCollectorBinding::instance();
                const auto binding = self.lookup(flow);
                if (!binding.collector) return;
                if (!binding.collector->accepting.load(std::memory_order_relaxed)) return;

                const auto& snaps = flow->drop_snapshots();
                const auto key = flow->flow_key();
                auto& shard = binding.collector->shard_for(binding.shard_index);

                std::lock_guard<std::mutex> lock(shard.mtx);
                if (!binding.collector->accepting.load(std::memory_order_relaxed)) return;
                // Mirror any updated packet drop snapshots from the FlowEngine into
                // the shared collector so aggregate decisions see fresh stats.
                for (const auto& pair : snaps) {
                    if (packet_id != 0 && pair.first != packet_id) continue;
                    self.upsert_locked(binding, key, pair.first, pair.second);
                }
            });
    });
}

void DropCollectorBinding::bind(penny::FlowEngine* flow,
                                DropCollectorPtr collector,
                                const std::string& thread_name,
                                std::size_t shard_index) {
    if (!flow || !collector) return;
    std::lock_guard<std::mutex> lock(mtx_);
    bindings_[flow] = BindingContext{
        std::move(collector),
        thread_name,
        shard_index
    };
}

void DropCollectorBinding::unbind(penny::FlowEngine* flow) {
    if (!flow) return;
    std::lock_guard<std::mutex> lock(mtx_);
    bindings_.erase(flow);
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
    upsert_locked(BindingContext{collector, thread_name, shard_index}, key, packet_id, snap);
}

DropCollectorBinding::BindingContext DropCollectorBinding::lookup(penny::FlowEngine* flow) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = bindings_.find(flow);
    if (it != bindings_.end()) {
        return it->second;
    }
    return {};
}

void DropCollectorBinding::upsert_locked(const BindingContext& binding,
                                         const FlowKey& key,
                                         penny::PacketDropId packet_id,
                                         const penny::PacketDropSnapshot& snap) {
    if (!binding.collector) return;
    auto& shard = binding.collector->shard_for(binding.shard_index);
    auto& snapshots = shard.snapshots;
    DropCollector::SnapshotKey snapshot_key{key, packet_id};

    auto index_it = shard.snapshot_index.find(snapshot_key);
    if (index_it != shard.snapshot_index.end()) {
        auto& rec = snapshots[index_it->second];
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
    } else {
        const auto idx = snapshots.size();
        snapshots.push_back(DropSnapshotRecord{key, packet_id, snap, {}, binding.thread_name});
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
    }
}

} // namespace openpenny::app
