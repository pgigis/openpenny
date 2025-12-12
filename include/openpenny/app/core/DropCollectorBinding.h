// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/agg/Stats.h"

#include <mutex>
#include <string>
#include <unordered_map>

namespace openpenny::penny {
class FlowEngine;
}

namespace openpenny::app {

/**
 * @brief Maintains FlowEngine -> DropCollector bindings and installs the
 * snapshot hook so drop events are mirrored into the shared collector.
 */
class DropCollectorBinding {
public:
    static DropCollectorBinding& instance();

    // Ensure the global timer snapshot hook is installed exactly once.
    void ensure_snapshot_hook();

    void bind(penny::FlowEngine* flow,
              DropCollectorPtr collector,
              const std::string& thread_name);

    void unbind(penny::FlowEngine* flow);

    void upsert(DropCollectorPtr collector,
                const std::string& thread_name,
                const FlowKey& key,
                const std::string& packet_id,
                const penny::PacketDropSnapshot& snap,
                const openpenny::app::AggregatedCounters& agg);

private:
    struct BindingContext {
        DropCollectorPtr collector;
        std::string thread_name;
    };

    DropCollectorBinding() = default;
    BindingContext lookup(penny::FlowEngine* flow) const;
    void upsert_locked(const BindingContext& binding,
                       const FlowKey& key,
                       const std::string& packet_id,
                       const penny::PacketDropSnapshot& snap,
                       const openpenny::app::AggregatedCounters& agg);

    mutable std::mutex mtx_;
    std::once_flag hook_once_;
    std::unordered_map<penny::FlowEngine*, BindingContext> bindings_;
};

} // namespace openpenny::app
