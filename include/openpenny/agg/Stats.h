// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file Stats.h
 * @brief Per-flow and aggregated statistics with a striped hash table.
 */
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <chrono>

namespace openpenny {

struct FlowKey {
    /**
     * @brief Tuple identifying a TCP/UDP flow in host byte order.
     */
    uint32_t src; uint32_t dst; uint16_t sport; uint16_t dport;
    bool operator==(const FlowKey& o) const noexcept {
        return src==o.src && dst==o.dst && sport==o.sport && dport==o.dport;
    }
};

struct FlowKeyHash {
    /**
     * @brief Mix all FlowKey fields into a single hash using 64-bit avalanching.
     */
    size_t operator()(const FlowKey& k) const noexcept {
        uint64_t v = (static_cast<uint64_t>(k.src) << 32) ^ k.dst;
        v ^= (static_cast<uint64_t>(k.sport) << 16) ^ k.dport;
        v ^= (v >> 33); v *= 0xff51afd7ed558ccdULL;
        v ^= (v >> 33); v *= 0xc4ceb9fe1a85ec53ULL;
        v ^= (v >> 33);
        return static_cast<size_t>(v);
    }
};

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
        std::unordered_map<FlowKey, Counters, FlowKeyHash> map;
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
