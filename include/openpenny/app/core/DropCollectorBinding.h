// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/agg/Stats.h"

#include <string>
#include <utility>
#include <vector>

namespace openpenny::app {

/**
 * @brief Mirrors per-flow drop snapshots into the shared collector.
 *
 * New drops are inserted one at a time via upsert(). Snapshot state changes
 * that affect a suffix of the per-flow snapshot vector (duplicate/rtx/expire)
 * are mirrored via refresh_from() so the collector can rescan the already
 * contiguous, append-only snapshot storage directly.
 */
class DropCollectorBinding {
public:
    static DropCollectorBinding& instance();

    void upsert(DropCollectorPtr collector,
                const std::string& thread_name,
                std::size_t shard_index,
                const FlowKey& key,
                penny::PacketDropId packet_id,
                const penny::PacketDropSnapshot& snap);

    void refresh_from(
        DropCollectorPtr collector,
        const std::string& thread_name,
        std::size_t shard_index,
        const FlowKey& key,
        const std::vector<std::pair<penny::PacketDropId, penny::PacketDropSnapshot>>& snapshots,
        std::size_t start_index);

private:
    DropCollectorBinding() = default;

    void upsert_locked(DropCollector& collector,
                       DropCollector::Shard& shard,
                       const std::string& thread_name,
                       const FlowKey& key,
                       penny::PacketDropId packet_id,
                       const penny::PacketDropSnapshot& snap);
};

} // namespace openpenny::app
