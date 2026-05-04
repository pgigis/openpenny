// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/FlowKey.h"
#include "openpenny/penny/flow/state/PacketDropId.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <functional>

namespace openpenny::penny {

// Forward declaration to avoid circular includes.
class FlowEngine;

/**
 * @brief Timer manager for scheduling and resolving packet drop snapshots.
 *
 * High-level design
 * -----------------
 *  - Each worker thread owns a thread-local manager instance.
 *  - Packet-processing code never mutates FlowEngine snapshots directly from nested
 *    helper paths. Instead, it:
 *      * register drops (with deadlines),
 *      * enqueue retransmission / duplicate events.
 *  - The worker periodically calls drain_callbacks(), which:
 *      * pops expired entries from a min-heap,
 *      * consumes queued events,
 *      * turns them into callbacks,
 *      * and executes those callbacks on the same worker thread.
 *
 * As a result:
 *  - All snapshot mutations stay on the queue worker that owns the flow.
 *  - We avoid one extra timer thread and the associated context switching per queue.
 */
class ThreadFlowEventTimerManager {
public:
    /**
     * @brief Access the thread-local timer manager instance.
     *
     * Each packet-processing thread gets its own manager, so queues are isolated.
     */
    static ThreadFlowEventTimerManager& instance();

    ~ThreadFlowEventTimerManager();

    /**
     * @brief Initialise the per-thread timer state with a given drop timeout.
     *
     * @param timeout_sec Timeout in seconds after which an un-repaired drop snapshot
     *                    is considered expired.
     */
    void start(double timeout_sec);

    /**
     * @brief Stop and flush internal state.
     *
     * Safe to call multiple times; subsequent calls after the first have no effect.
     */
    void stop();

    /**
     * @brief Register a drop snapshot for expiration.
     *
     * Schedules a drop associated with @p packet_id to expire at @p ts + timeout_sec_
     * (configured via start()).
     *
     * @param key            Flow key of the drop.
     * @param packet_id      Logical identifier of the dropped packet.
     * @param ts             Observation timestamp of the drop.
     * @param flow_alive     Shared liveness flag owned by the FlowEngine instance.
     * @param flow           Pointer to the owning FlowEngine (not owned by the manager).
     * @param snapshot_index Index of the snapshot inside FlowEngine::flow_drop_snapshots_.
     */
    void register_drop(const ::openpenny::FlowKey& key,
                       PacketDropId packet_id,
                       std::chrono::steady_clock::time_point ts,
                       std::shared_ptr<bool> flow_alive,
                       FlowEngine* flow,
                       std::size_t snapshot_index);

    /**
     * @brief Queue an asynchronous "retransmitted" event from the packet path.
     *
     * The owning worker thread will later convert this into a callback that
     * updates the relevant snapshot in the owning FlowEngine.
     */
    void enqueue_retransmitted(PacketDropId packet_id, FlowEngine* flow);

    /**
     * @brief Queue an asynchronous "duplicate" event from the packet path.
     *
     * Used to track duplicate sequence numbers and evaluate thresholds without
     * mutating FlowEngine directly on the hot path.
     */
    void enqueue_duplicate(FlowEngine* flow, std::uint32_t seq, std::uint32_t payload);

    /**
     * @brief Cancel all timeouts and queued callbacks associated with a flow.
     *
     * Typically called when a FlowEngine is destroyed or monitoring ends, to
     * ensure no timers or callbacks reference freed memory.
     */
    void purge_flow(FlowEngine* flow);

    /**
     * @brief Drain due expirations and queued events on the current worker thread.
     */
    void drain_callbacks();

private:
    // ---------------------------------------------------------------------
    // Internal helper types
    // ---------------------------------------------------------------------

    /**
     * @brief Timer entry representing a scheduled drop expiry.
     */
    struct Entry {
        std::uint64_t token{0};    ///< Unique token for cancellation / tracking.
        std::chrono::steady_clock::time_point deadline{}; ///< Expiry time.
        ::openpenny::FlowKey key{};   ///< Flow key for logging / debugging.
        PacketDropId packet_id{0};    ///< Snapshot identifier within the flow.
        std::weak_ptr<bool> flow_alive; ///< Liveness flag to avoid calling dead flows.
        FlowEngine* flow{nullptr};      ///< Non-owning pointer to the FlowEngine.
        std::size_t snapshot_index{0}; ///< Index into the flow's snapshot vector.
    };

    /**
     * @brief Comparator for the timer min-heap (earliest deadline at top).
     */
    struct EntryDeadlineCompare {
        bool operator()(const Entry& a, const Entry& b) const noexcept {
            // Min-heap by deadline.
            return a.deadline > b.deadline;
        }
    };

    /**
     * @brief Key used to find a timer entry by (flow, packet_id).
     *
     * Lets us quickly locate and cancel a specific drop by packet_id.
     */
    struct PacketKey {
        FlowEngine* flow{nullptr};
        PacketDropId packet_id{0};

        bool operator==(const PacketKey& other) const noexcept {
            return flow == other.flow && packet_id == other.packet_id;
        }
    };

    struct PacketKeyHash {
        std::size_t operator()(const PacketKey& k) const noexcept {
            std::size_t h1 = std::hash<FlowEngine*>{}(k.flow);
            std::size_t h2 = std::hash<PacketDropId>{}(k.packet_id);
            return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
        }
    };

    /**
     * @brief Event generated by the packet path and consumed by drain_callbacks().
     *
     * These events are cheap to enqueue in the packet-processing context and
     * later turned into callbacks against FlowEngine.
     */
    struct Event {
        enum class Kind {
            Retransmit,
            Duplicate
        };

        Kind kind{Kind::Retransmit};
        PacketDropId packet_id{0}; ///< For retransmit events.
        FlowEngine* flow{nullptr}; ///< Target flow; not owned.
        std::uint32_t seq{0};     ///< For duplicate events.
        std::uint32_t payload{0}; ///< Payload size for duplicate events.
    };

    /**
     * @brief Callback to be executed against FlowEngine on the worker thread.
     *
     * This is the only place where snapshots and FlowEngine state are mutated.
     */
    struct Callback {
        enum class Kind {
            Expire,      ///< A scheduled drop snapshot expired.
            Retransmit,  ///< A retransmit repaired a drop.
            Duplicate    ///< A duplicate sequence was observed for the flow.
        };

        Kind kind{Kind::Expire};
        PacketDropId packet_id{0}; ///< For Expire / Retransmit callbacks.
        FlowEngine* flow{nullptr}; ///< Target flow; not owned.
        std::uint32_t seq{0};     ///< For Duplicate callbacks.
    };

    ThreadFlowEventTimerManager() = default;
    ThreadFlowEventTimerManager(const ThreadFlowEventTimerManager&) = delete;
    ThreadFlowEventTimerManager& operator=(const ThreadFlowEventTimerManager&) = delete;

    // Run and clear the callbacks in @p pending, without holding mutex_.
    void run_callbacks(std::deque<Callback>& pending);

    // Collect all due expirations and queued events into @p pending (mutex_ held).
    void collect_ready_callbacks(std::deque<Callback>& pending,
                                 const std::chrono::steady_clock::time_point& now);

    // Discard cancelled heap entries and refresh the lock-free earliest-deadline hint (mutex_ held).
    void refresh_next_deadline_locked();

    // ---------------------------------------------------------------------
    // Synchronisation / thread state
    // ---------------------------------------------------------------------

    std::mutex mutex_;
    using DeadlineRep = std::chrono::steady_clock::duration::rep;
    static constexpr DeadlineRep kNoDeadline = std::numeric_limits<DeadlineRep>::max();

    bool running_{false};    ///< True once start() has initialised this worker-local manager.
    double timeout_sec_{0.0};
    std::uint64_t next_token_{1};

    // ---------------------------------------------------------------------
    // Timer state
    // ---------------------------------------------------------------------

    /// Min-heap of scheduled drop expiries ordered by deadline.
    std::priority_queue<Entry, std::vector<Entry>, EntryDeadlineCompare> heap_;

    /// Lookup from (flow, packet_id) to the corresponding timer entry.
    std::unordered_map<PacketKey, Entry, PacketKeyHash> by_id_;

    /// Record of flow+packet_id pairs already handled as retransmitted.
    std::unordered_set<PacketKey, PacketKeyHash> retransmit_seen_;

    /// Map from FlowEngine* to active timer tokens (for bulk purge_flow()).
    std::unordered_multimap<FlowEngine*, std::uint64_t> by_flow_;

    /// Set of tokens that have been cancelled but might still be in the heap.
    std::unordered_set<std::uint64_t> cancelled_;

    // ---------------------------------------------------------------------
    // Asynchronous events and callbacks
    // ---------------------------------------------------------------------

    /// Events queued by the packet-processing path for drain_callbacks().
    std::deque<Event> events_;

    /**
     * @brief Lock-free fast-path size of `events_`.
     *
     * This lets drain_callbacks() skip taking mutex_ when there are no queued
     * retransmit/duplicate events and no drop deadline has elapsed yet.
     */
    std::atomic<std::size_t> queued_event_count_{0};

    /// Lock-free hint for the earliest outstanding drop deadline.
    std::atomic<DeadlineRep> next_deadline_{kNoDeadline};

};

} // namespace openpenny::penny
