// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/state/PennyStats.h"
#include "openpenny/net/Packet.h"
#include "openpenny/app/core/PerThreadStats.h"

#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <chrono>

namespace openpenny::penny {

/**
 * @brief High level monitoring state for a flow in the table.
 *
 * This tracks where we are in the flow lifecycle from the perspective of
 * Penny’s monitoring logic, not the TCP state machine itself.
 */
enum class FlowTrackingState {
    PENDING,                          ///< Flow seen but not yet active (no useful evidence).
    ACTIVE_SEEN_SYN,                  ///< Flow is active and we have observed a SYN.
    PENDING_SEEN_DATA,                ///< Data seen, still waiting for enough evidence to activate.
    ACTIVE_SEEN_DATA,                 ///< Activated as data bearing flow (without SYN).
    INTERRUPTED_RST,                  ///< Monitoring interrupted due to RST.
    INTERRUPTED_DUPLICATE_EXCEEDED,   ///< Stopped as duplicate threshold was exceeded.
    INTERRUPTED_OUT_OF_ORDER_EXCEEDED,///< Stopped as out of order threshold was exceeded.
    CONNECTION_CLOSED_FIN,            ///< Connection closed cleanly via FIN.
    FINISHED,                         ///< Flow fully processed and decision taken.
    NOT_ACTIONABLE                    ///< Flow is not present or no longer actionable.
};

/**
 * @brief Whether to skip or process a given packet through Penny.
 *
 * @brief Table entry that bundles per flow state and its FlowEngine instance.
 */
struct FlowEngineEntry {
    FlowEngine flow{};                         ///< Per flow Penny logic and statistics.
    FlowTrackingState state{FlowTrackingState::PENDING}; ///< Monitoring state for this flow.
    std::chrono::steady_clock::time_point last_seen{};
    std::chrono::steady_clock::time_point first_seen{};
};

/**
 * @brief Flow table managing FlowEngine instances for multiple concurrent flows.
 *
 * Responsibilities:
 *  - Create, configure, and own FlowEngine objects keyed by FlowKey.
 *  - Track per flow monitoring state and transitions across the flow lifecycle.
 *  - Decide whether incoming packets should be processed or skipped.
 *  - Enforce capacity limits on the number of concurrently monitored flows.
 *
 * Threading model:
 *  - All methods are expected to be called from the packet-processing thread.
 *  - No synchronisation primitives are used inside this class.
 */
class ThreadFlowManager {
public:
    /// Construct an empty table with default configuration.
    ThreadFlowManager();

    /// Construct an empty table with the provided Penny configuration.
    explicit ThreadFlowManager(const Config::ActiveConfig& cfg);

    /**
     * @brief Install or update the Penny configuration for all future flows.
     *
     * Existing flows are not automatically reset, but new entries created after
     * this call will use the updated configuration.
     */
    void configure(const Config::ActiveConfig& cfg);

    /**
     * @brief Check if the given flow key is currently associated with a monitored flow.
     *
     * @return true if there is an active or tracked FlowEngineEntry for @p key.
     */
    bool packet_in_context(const FlowKey& key) const noexcept {
        return table_active_flows_.find(key) != table_active_flows_.end();
    }

    /**
     * @brief Test whether adding another actively monitored flow would exceed capacity.
     *
     * Returns true when adding one more active flow would surpass the configured maximum
     * (table_cfg_.max_tracked_flows). If the maximum is zero, capacity is
     * treated as unbounded.
     */
    bool is_flow_monitoring_capacity_full() const noexcept {
        const auto maxActiveFlowsAllowed = table_cfg_.max_tracked_flows;

        // A value of 0 disables the monitoring cap.
        if (maxActiveFlowsAllowed == 0) {
            return false;
        }

        // Get a lock-free snapshot of active flows currently tracked across all threads.
        const auto totalActiveFlowsNow = openpenny::app::aggregate_active_flows();

        // If we are already at or beyond the cap, treat capacity as full.
        if (totalActiveFlowsNow >= maxActiveFlowsAllowed) {
            return true;
        }

        // Final check: compare the local thread's active flow count with the global budget.
        // This ensures we do not admit a new flow when the current worker is also at its share.
        return active_flow_count(table_cfg_.max_tracked_flows) >= maxActiveFlowsAllowed;
    }

    /**
     * @brief Insert and bootstrap a new monitored flow from the first observed packet.
     *
     * This is typically called when we have decided to start tracking a new flow.
     *
     * @param key           Flow key (four or five tuple) identifying the flow.
     * @param seq           TCP sequence number of the first packet.
     * @param payload_bytes Payload length of the first packet (to support TFO / data first).
     * @param is_syn        True if the first packet carried a SYN flag.
     * @param ts            Timestamp of the first packet (for data timing).
     *
     * @return true if a new flow entry was inserted, false if the flow already existed
     *         or had been monitored before.
     */
    bool add_new_flow(const FlowKey& key,
                      uint32_t seq,
                      uint32_t payload_bytes,
                      bool is_syn,
                      const std::chrono::steady_clock::time_point& ts);

    /// Install a sink that receives drop snapshots from all managed FlowEngines.
    void set_drop_sink(FlowEngine::DropSnapshotSink sink);

    /**
     * @brief Update or create the FlowEngine entry corresponding to a packet.
     *
     * High level behaviour:
     *  1. Lookup or create the entry in the table. New flows are configured and start
     *     in PENDING state.
     *  2. If the packet carries a SYN, immediately mark the flow ACTIVE_SEEN_SYN,
     *     record the SYN sequence, and return (SYNs need no further state transitions).
     *  3. For data packets we transition between PENDING / PENDING_SEEN_DATA /
     *     ACTIVE_SEEN_DATA depending on whether we have observed a SYN and how long
     *     the flow has been data only.
     *  4. If the flow has been data only long enough (rtt_timeout_factor in seconds) we promote it to
     *     ACTIVE_SEEN_DATA.
     *  5. Finally we call record_packet() on the underlying FlowEngine so per flow
     *     counters stay in sync and hand the caller the entry decision.
     *
     * @param packet Incoming packet view from the data path.
     * @param ts     Timestamp for this packet.
     */
    void track_packet(const ::openpenny::net::PacketView& packet,
                      const std::chrono::steady_clock::time_point& ts);

    /**
     * @brief Check whether a flow identified by @p key was already completed.
     *
     * This is useful to avoid re tracking flows that we have already fully processed.
     */
    bool was_completed(const FlowKey& key) const noexcept {
        return table_completed_flows_.find(key) != table_completed_flows_.end();
    }

    /**
     * @brief Find a mutable entry for @p key, or nullptr if it is not active.
     */
    FlowEngineEntry* find(const FlowKey& key) {
        auto it = table_active_flows_.find(key);
        return (it == table_active_flows_.end()) ? nullptr : &it->second;
    }

    /**
     * @brief Find a const entry for @p key, or nullptr if it is not active.
     */
    const FlowEngineEntry* find(const FlowKey& key) const {
        auto it = table_active_flows_.find(key);
        return (it == table_active_flows_.end()) ? nullptr : &it->second;
    }

    /**
     * @brief Return the monitoring state for the given flow key.
     *
     * If the flow is not present in the active table, NOT_ACTIONABLE is returned.
     */
    FlowTrackingState flow_state(const FlowKey& key) const noexcept {
        auto it = table_active_flows_.find(key);
        if (it == table_active_flows_.end()) {
            return FlowTrackingState::NOT_ACTIONABLE;
        }
        return it->second.state;
    }

    /**
     * @brief Mark a flow as completed and move it to the completed set.
     *
     * This is expected to be called when Penny has taken a final decision for
     * this flow or when further monitoring is no longer useful.
     *
     * @return true if the flow was present and is now marked as completed.
     */
    bool complete_flow(const FlowKey& key, const char* reason = "completed");

    /// Update the last seen timestamp for an active flow (no-op if absent).
    void touch_flow(const FlowKey& key,
                    const std::chrono::steady_clock::time_point& ts);

    /**
     * @brief Return the set of flows whose last_seen exceeds the given timeout.
     *
     * @param now     Reference time.
     * @param timeout Duration threshold; non-positive disables expiry.
     */
    std::vector<FlowKey> collect_idle_flows(const std::chrono::steady_clock::time_point& now,
                                            const std::chrono::steady_clock::duration& timeout) const;

    /// Erase an active flow entry if present.
    void erase(const FlowKey& key) { table_active_flows_.erase(key); }

    /// Clear all active flows (completed set is left untouched).
    void clear() { table_active_flows_.clear(); }

    /// Number of entries currently present in the active flow table.
    std::size_t size() const noexcept { return table_active_flows_.size(); }

    /**
     * @brief Apply a function to every active flow entry.
     *
     * @tparam Fn Callable with signature `void(const FlowKey&, FlowEngineEntry&)`.
     */
    template <typename Fn>
    void for_each_flow(Fn&& fn) {
        for (auto& kv : table_active_flows_) {
            fn(kv.first, kv.second);
        }
    }

    /**
     * @brief Apply a function to every active flow entry (const version).
     *
     * @tparam Fn Callable with signature `void(const FlowKey&, const FlowEngineEntry&)`.
     */
    template <typename Fn>
    void for_each_flow(Fn&& fn) const {
        for (const auto& kv : table_active_flows_) {
            fn(kv.first, kv.second);
        }
    }

private:
    /**
     * @brief Count how many flows are currently considered "active".
     *
     * This counts every entry present in the active table. This is used to
     * enforce capacity limits.
     *
     * @param stop_after If non maximal, stop counting once this many active flows
     *                   have been found (micro optimisation for capacity checks).
     */
    std::size_t active_flow_count(
        std::size_t stop_after = std::numeric_limits<std::size_t>::max()) const noexcept
    {
        if (stop_after == std::numeric_limits<std::size_t>::max()) {
            return table_active_flows_.size();
        }
        return std::min(table_active_flows_.size(), stop_after);
    }

    /// Global configuration applied when creating new FlowEngine instances.
    Config::ActiveConfig table_cfg_{};

    /// Aggregated Penny statistics (to be maintained by callers).
    PennyStats stats_{};

    /// Map from flow key to the corresponding FlowEngineEntry for active or tracked flows.
    std::unordered_map<FlowKey, FlowEngineEntry, FlowKeyHash> table_active_flows_;

    /// Set of flow keys that have already been fully processed / completed.
    std::unordered_set<FlowKey, FlowKeyHash> table_completed_flows_;

    FlowEngine::DropSnapshotSink drop_sink_{};
};

} // namespace openpenny::penny
