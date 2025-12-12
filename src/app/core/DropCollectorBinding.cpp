// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/DropCollectorBinding.h"

#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <algorithm>
#include <utility>

namespace openpenny::app {

DropCollectorBinding& DropCollectorBinding::instance() {
    static DropCollectorBinding inst;
    return inst;
}

void DropCollectorBinding::ensure_snapshot_hook() {
    std::call_once(hook_once_, []() {
        penny::ThreadFlowEventTimerManager::set_snapshot_hook(
            [](penny::FlowEngine* flow,
               const std::string& packet_id,
               penny::ThreadFlowEventTimerManager::SnapshotEventKind /*kind*/) {
                auto& self = DropCollectorBinding::instance();
                const auto binding = self.lookup(flow);
                if (!binding.collector) return;

                const auto agg = openpenny::app::aggregate_counters();
                const auto& snaps = flow->drop_snapshots();
                const auto key = flow->flow_key();

                std::lock_guard<std::mutex> lock(binding.collector->mtx);
                if (!binding.collector->accepting.load(std::memory_order_relaxed)) return;
                // Mirror any updated packet drop snapshots from the FlowEngine into
                // the shared collector so aggregate decisions see fresh stats.
                for (const auto& pair : snaps) {
                    if (!packet_id.empty() && pair.first != packet_id) continue;
                    auto snap = pair.second;
                    snap.stats.overwrite_from_aggregates(agg);
                    self.upsert_locked(binding, key, pair.first, snap, agg);
                }
            });
    });
}

void DropCollectorBinding::bind(penny::FlowEngine* flow,
                                DropCollectorPtr collector,
                                const std::string& thread_name) {
    if (!flow || !collector) return;
    std::lock_guard<std::mutex> lock(mtx_);
    bindings_[flow] = BindingContext{std::move(collector), thread_name};
}

void DropCollectorBinding::unbind(penny::FlowEngine* flow) {
    if (!flow) return;
    std::lock_guard<std::mutex> lock(mtx_);
    bindings_.erase(flow);
}

void DropCollectorBinding::upsert(DropCollectorPtr collector,
                                  const std::string& thread_name,
                                  const FlowKey& key,
                                  const std::string& packet_id,
                                  const penny::PacketDropSnapshot& snap,
                                  const openpenny::app::AggregatedCounters& agg) {
    if (!collector) return;
    std::lock_guard<std::mutex> lock(collector->mtx);
    if (!collector->accepting.load(std::memory_order_relaxed)) return;
    upsert_locked(BindingContext{collector, thread_name}, key, packet_id, snap, agg);
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
                                         const std::string& packet_id,
                                         const penny::PacketDropSnapshot& snap,
                                         const openpenny::app::AggregatedCounters& agg) {
    if (!binding.collector) return;
    auto& snapshots = binding.collector->snapshots;
    auto it = std::find_if(
        snapshots.begin(),
        snapshots.end(),
        [&](const DropSnapshotRecord& rec) {
            return rec.packet_id == packet_id &&
                   rec.thread_name == binding.thread_name &&
                   rec.key == key;
        });

    if (it != snapshots.end()) {
        it->snapshot = snap;
        it->counters = agg;
    } else {
        snapshots.push_back(DropSnapshotRecord{key, packet_id, snap, agg, binding.thread_name});
    }
}

} // namespace openpenny::app
