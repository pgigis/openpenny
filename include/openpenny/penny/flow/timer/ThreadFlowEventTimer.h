// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/Stats.h" // for FlowKey

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
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
 *  - A single background thread runs timer_loop().
 *  - Packet-processing threads never mutate FlowEngine snapshots directly. Instead, they:
 *      * register drops (with deadlines),
 *      * enqueue retransmission / duplicate events.
 *  - The timer thread:
 *      * pops expired entries from a min-heap,
 *      * consumes queued events,
 *      * turns them into callbacks,
 *      * and executes those callbacks itself (without holding the manager mutex).
 *
 * As a result:
 *  - All snapshot mutations are single-threaded (in the timer thread).
 *  - The packet path stays lightweight and avoids locking around FlowEngine state.
 */
class ThreadFlowEventTimerManager {
public:
    /**
     * @brief Access the thread-local timer manager instance.
     *
     * Each packet-processing thread gets its own manager (and timer thread),
     * so queues are isolated.
     */
    static ThreadFlowEventTimerManager& instance();

    ~ThreadFlowEventTimerManager();

    /**
     * @brief Start the timer thread with a given drop timeout.
     *
     * @param timeout_sec Timeout in seconds after which an un-repaired drop snapshot
     *                    is considered expired.
     */
    void start(double timeout_sec);

    /**
     * @brief Stop the timer thread and flush internal state.
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
                       const std::string& packet_id,
                       std::chrono::steady_clock::time_point ts,
                       std::shared_ptr<bool> flow_alive,
                       FlowEngine* flow,
                       std::size_t snapshot_index);

    /**
     * @brief Queue an asynchronous "retransmitted" event from the packet path.
     *
     * The timer thread will later convert this into a callback that updates
     * the relevant snapshot in the owning FlowEngine.
     */
    void enqueue_retransmitted(const std::string& packet_id, FlowEngine* flow);

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
     * @brief Optional manual draining of callbacks.
     *
     * Historically used when callbacks were executed from the packet-processing
     * thread; kept for compatibility. In the current design, the timer thread
     * is responsible for draining and executing callbacks via run_callbacks().
     */
    void drain_callbacks();

    enum class SnapshotEventKind { Expire, Retransmit, Duplicate };

    /**
     * @brief Install a hook invoked after a snapshot event is applied.
     *
     * The hook runs in the packet-processing thread context when callbacks
     * are drained.
     */
    static void set_snapshot_hook(std::function<void(FlowEngine*,
                                                     const std::string&,
                                                     SnapshotEventKind)> hook);

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
        std::string packet_id{};      ///< Snapshot identifier within the flow.
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
        std::string packet_id{};

        bool operator==(const PacketKey& other) const noexcept {
            return flow == other.flow && packet_id == other.packet_id;
        }
    };

    struct PacketKeyHash {
        std::size_t operator()(const PacketKey& k) const noexcept {
            std::size_t h1 = std::hash<FlowEngine*>{}(k.flow);
            std::size_t h2 = std::hash<std::string>{}(k.packet_id);
            return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
        }
    };

    /**
     * @brief Event generated by the packet path and consumed by the timer thread.
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
        std::string packet_id{};  ///< For retransmit events.
        FlowEngine* flow{nullptr}; ///< Target flow; not owned.
        std::uint32_t seq{0};     ///< For duplicate events.
        std::uint32_t payload{0}; ///< Payload size for duplicate events.
    };

    /**
     * @brief Callback to be executed against FlowEngine by the timer thread.
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
        std::string packet_id{};  ///< For Expire / Retransmit callbacks.
        FlowEngine* flow{nullptr}; ///< Target flow; not owned.
        std::uint32_t seq{0};     ///< For Duplicate callbacks.
    };

    ThreadFlowEventTimerManager() = default;
    ThreadFlowEventTimerManager(const ThreadFlowEventTimerManager&) = delete;
    ThreadFlowEventTimerManager& operator=(const ThreadFlowEventTimerManager&) = delete;

    // Main thread loop: waits for timers or events, then processes them.
    void timer_loop();

    // Notify the timer thread that new timers/events are available (mutex_ held).
    void wake_locked();

    // Run and clear the callbacks in @p pending, without holding mutex_.
    void run_callbacks(std::deque<Callback>& pending);

    // ---------------------------------------------------------------------
    // Synchronisation / thread state
    // ---------------------------------------------------------------------

    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread thread_;

    bool running_{false};    ///< True once the timer thread has been started.
    bool stop_flag_{false};  ///< Set to request shutdown of the timer thread.
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
    std::vector<PacketKey> retransmit_seen_;

    /// Map from FlowEngine* to active timer tokens (for bulk purge_flow()).
    std::unordered_multimap<FlowEngine*, std::uint64_t> by_flow_;

    /// Set of tokens that have been cancelled but might still be in the heap.
    std::unordered_set<std::uint64_t> cancelled_;

    // ---------------------------------------------------------------------
    // Asynchronous events and callbacks
    // ---------------------------------------------------------------------

    /// Events queued by the packet-processing path for the timer thread.
    std::deque<Event> events_;

    /**
     * @brief Pending callbacks to execute against FlowEngine.
     *
     * These are built while holding mutex_, but always executed by the timer
     * thread via run_callbacks() without the lock, avoiding lock contention
     * during snapshot updates.
     */
    std::deque<Callback> callbacks_;

    static std::function<void(FlowEngine*, const std::string&, SnapshotEventKind)> snapshot_hook_;
};

} // namespace openpenny::penny
