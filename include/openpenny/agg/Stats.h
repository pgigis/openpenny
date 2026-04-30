// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file Stats.h
 * @brief Per-flow and aggregated statistics with a striped hash table.
 */
#include "openpenny/agg/FlowKey.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <shared_mutex>
#include <mutex>
#include <chrono>

namespace openpenny {

/**
 * @brief Per-flow counters that mirror the BPF-side stats exposed to users.
 */
struct Counters { uint64_t packets{0}, bytes{0}, syn{0}, fin{0}, rst{0}; };

/**
 * @brief Thread-safe hash table of FlowKey -> Counters with striped locks.
 */
class FlowTable {
public:
    explicit FlowTable(size_t stripes = 64) : shards_(stripes) {}

    /**
     * @brief Merge a packet sample into the per-flow table.
     */
    void add(const FlowKey& k, uint64_t bytes, uint8_t tcp_flags) {
        auto& shard = shards_[hash_(k) % shards_.size()];
        std::unique_lock lk(shard.mutex);
        auto& c = shard.map[k];
        c.packets += 1; c.bytes += bytes;
        if (tcp_flags & 0x02) c.syn++; // SYN
        if (tcp_flags & 0x01) c.fin++; // FIN
        if (tcp_flags & 0x04) c.rst++; // RST
    }

    /**
     * @brief Take a snapshot of the table contents.
     */
    std::vector<std::pair<FlowKey, Counters>> snapshot() const {
        std::vector<std::pair<FlowKey, Counters>> all;
        for (auto& shard : shards_) {
            std::shared_lock lk(shard.mutex);
            all.reserve(all.size() + shard.map.size());
            for (auto& kv : shard.map) all.push_back(kv);
        }
        return all;
    }

    /**
     * @brief Remove all tracked flows.
     */
    void clear() {
        for (auto& shard : shards_) {
            std::unique_lock lk(shard.mutex);
            shard.map.clear();
        }
    }

private:
    struct Shard {
        mutable std::shared_mutex mutex;
        FlowMap<Counters> map;
    };
    std::vector<Shard> shards_;
    FlowKeyHash hash_;
};

/**
 * @brief Aggregate counters across all flows using atomic accumulation.
 */
struct Aggregated {
    std::atomic<uint64_t> packets{0}, bytes{0}, syn{0}, fin{0}, rst{0};
    void add(const Counters& c){ packets+=c.packets; bytes+=c.bytes; syn+=c.syn; fin+=c.fin; rst+=c.rst; }
};

} // namespace openpenny
