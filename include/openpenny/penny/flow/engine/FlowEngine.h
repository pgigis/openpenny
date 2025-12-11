// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/Stats.h"
#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"
#include "openpenny/penny/flow/state/PennyStats.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"

#include <functional>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/icl/interval_set.hpp>

namespace icl = boost::icl;

namespace openpenny::penny {

/**
 * @brief Per-flow state machine for Penny.
 *
 * FlowEngine tracks TCP sequence space coverage, packet drops, retransmissions,
 * and duplicate / out-of-order behaviour for a single flow. It owns the per-flow
 * statistics and the bookkeeping required to link drops to later repairs.
 *
 * Threading model:
 *  - State is mutated only from the packet-processing thread.
 *  - Timer callbacks are drained into that same thread via
 *    ThreadFlowEventTimerManager::drain_callbacks().
 *  - As a result, no explicit locking is required inside this class.
 */
class FlowEngine {
public:
    using DropSnapshotSink = std::function<void(const FlowKey&,
                                                const std::string&,
                                                const PacketDropSnapshot&)>;

    /// High-level decision / outcome for this flow.
    enum class FlowDecision {
        PENDING,                   ///< No decision yet.
        FINISHED_CLOSED_LOOP,      ///< Flow classified as closed-loop.
        FINISHED_NOT_CLOSED_LOOP,  ///< Flow classified as not closed-loop.
        FINISHED_DUPLICATE_EXCEEDED, ///< Flow exceeded duplicate threshold.
        FINISHED_NO_DECISION       ///< Flow ended without enough evidence for a decision.
    };

    // ---------------------------------------------------------------------
    // Construction / configuration / lifecycle
    // ---------------------------------------------------------------------

    /// Construct with default configuration (must later call configure()).
    FlowEngine();

    /// Construct with an initial Penny configuration.
    explicit FlowEngine(const Config::ActiveConfig& cfg);

    /// Destructor flips the liveness flag so pending timers can be ignored.
    ~FlowEngine();

    /**
     * @brief Install or update the Penny configuration for this flow.
     *
     * This does not automatically reset the existing statistics or gaps.
     * Call reset() explicitly if you want a fresh flow state.
     */
    void configure(const Config::ActiveConfig& cfg);

    /**
     * @brief Reset all per-flow state.
     *
     * Clears statistics, sequence/gap tracking, drop snapshots, and cached
     * decisions. The configuration itself is preserved.
     */
    void reset();

    /// Return the cached classification decision made for this flow.
    FlowDecision final_decision() const noexcept { return flow_final_decision_; }

    // ---------------------------------------------------------------------
    // High-level stats / configuration accessors
    // ---------------------------------------------------------------------

    /// Number of packets that were eligible to be dropped according to policy.
    uint64_t droppable_packets() const noexcept { return flow_stats_.droppable_packets(); }

    /// Number of packets for which Penny actually enforced a drop.
    uint64_t enforced_drops() const noexcept { return flow_drops_enforced_; }

    /// Number of packets marked as duplicates.
    uint64_t duplicates() const noexcept { return flow_stats_.duplicate_packets(); }

    /// Read-only access to the effective Penny configuration for this flow.
    const Config::ActiveConfig& config() const noexcept { return flow_cfg_; }

    // ---------------------------------------------------------------------
    // Packet / sequence tracking entry points
    // ---------------------------------------------------------------------

    /**
     * @brief Record the SYN sequence number for this flow.
     *
     * This is typically the first contact with sequence space and is used
     * to normalise further sequence tracking.
     */
    void record_syn(uint32_t seq);

    /**
     * @brief Record a data packet in the sequence space.
     *
     * @param seq The starting sequence number of the data.
     * @param ts  Timestamp when the packet was observed.
     */
    void record_data(uint32_t seq, const std::chrono::steady_clock::time_point& ts);

    /// Highest sequence number observed so far (normalised to flow_stats_ convention).
    uint32_t highest_sequence() const noexcept { return flow_stats_.highest_seq(); }

    /// True if we have seen at least one sequence-bearing packet.
    bool has_sequence_sample() const noexcept { return flow_has_seen_sequence_; }

    // ---------------------------------------------------------------------
    // Generic per-packet counters
    // (Call these from the packet-processing path as appropriate.)
    // ---------------------------------------------------------------------

    /// Increment the global "packets seen" counter for this flow.
    void record_packet();

    /// Record a pure ACK packet (no payload).
    void record_pure_ack();

    /// Record a data-bearing packet (may be in-order or out-of-order).
    void record_data_packet();

    /// Record a packet classified as duplicate.
    void record_duplicate_packet();

    /// Record a packet that is considered droppable according to Penny policy.
    void record_droppable_packet();

    // ---------------------------------------------------------------------
    // Flow identity
    // ---------------------------------------------------------------------

    /// Attach the 5-tuple (or equivalent) key to this flow.
    void set_flow_key(const FlowKey& key) noexcept { flow_key_ = key; }

    /// Return the flow key (5-tuple) associated with this FlowEngine.
    FlowKey flow_key() const noexcept { return flow_key_; }

    // ---------------------------------------------------------------------
    // Detailed per-flow statistics passthrough
    // ---------------------------------------------------------------------

    uint64_t packets_seen() const noexcept { return flow_stats_.packets_seen(); }
    uint64_t pure_ack_packets() const noexcept { return flow_stats_.pure_ack_packets(); }
    uint64_t data_packets() const noexcept { return flow_stats_.data_packets(); }
    uint64_t duplicate_packets() const noexcept { return flow_stats_.duplicate_packets(); }
    uint64_t in_order_packets() const noexcept { return flow_stats_.in_order_packets(); }
    uint64_t out_of_order_packets() const noexcept { return flow_stats_.out_of_order_packets(); }
    uint64_t retransmitted_packets() const noexcept { return flow_stats_.retransmitted_packets(); }
    uint64_t non_retransmitted_packets() const noexcept { return flow_stats_.non_retransmitted_packets(); }
    uint64_t dropped_packets() const noexcept { return flow_stats_.dropped_packets(); }
    uint64_t pending_retransmissions() const noexcept { return flow_stats_.pending_retransmissions(); }

    /// Timestamp of the first data packet seen (if any).
    std::optional<std::chrono::steady_clock::time_point> first_data_time() const noexcept {
        return flow_first_data_time_;
    }

    /// All recorded packet-drop snapshots, in observation order.
    const std::vector<std::pair<std::string, PacketDropSnapshot>>&
    drop_snapshots() const noexcept {
        return flow_drop_snapshots_;
    }

    /// Install a sink to receive drop snapshots as they are created.
    void set_drop_sink(DropSnapshotSink sink);

    // ---------------------------------------------------------------------
    // Sequence interval classification
    // ---------------------------------------------------------------------

    /**
     * @brief Classification of a [start, end) interval with respect to the
     *        current view of the sequence space.
     */
    struct IntervalMark {
        bool in_sequence{false};  ///< True if the interval is in-order / contiguous.
        bool duplicate{false};    ///< True if the interval overlaps already-covered bytes.
        bool touches_gap{false};  ///< True if the interval intersects any known drop gap.
    };

    /**
     * @brief Determine how a [start, end) interval relates to in-order,
     *        duplicate, and gap regions.
     *
     * This is typically called after updating coverage to decide whether the
     * packet should be interpreted as in-order, duplicate, or filling gaps.
     */
    IntervalMark mark_interval(uint32_t start, uint32_t end);

    /**
     * @brief Update in-order / out-of-order tracking given @p seq.
     *
     * @return true if the packet is considered in-order, false if out-of-order.
     */
    bool track_ordering(uint32_t seq);

    /**
     * @brief Update the highest observed sequence number if @p seq extends it.
     */
    void update_highest_sequence(uint32_t seq);

    // ---------------------------------------------------------------------
    // Gap tracking: linking dropped bytes to later repairs / retransmissions
    // ---------------------------------------------------------------------

    /**
     * @brief Register that bytes in [start, end) were intentionally dropped.
     *
     * The drop is associated with @p packet_id so that future retransmissions
     * filling this interval can be matched back to the original decision.
     */
    void register_gap(uint32_t start, uint32_t end, const std::string& packet_id);

    /**
     * @brief True if [start, end) lies strictly within gap space (no new coverage).
     *
     * This is useful to distinguish packets that only re-send bytes we have
     * already dropped from those that also extend coverage.
     */
    bool fills_only_gap_space(uint32_t start, uint32_t end) const;

    /**
     * @brief Fill gaps intersected by [start, end).
     *
     * Marks gap intervals as (partially) repaired and returns the packet_ids
     * of all affected gaps, in the order encountered.
     *
     * @param start            Start sequence of the repair interval.
     * @param end              End sequence of the repair interval.
     * @param partially_filled Optional out-parameter set to true if at least one
     *                         gap is only partially repaired.
     */
    std::vector<std::string> fill_gaps(uint32_t start,
                                       uint32_t end,
                                       bool* partially_filled = nullptr);

    /**
     * @brief Mark the given gap packet_ids as fully repaired.
     *
     * Typically called after fill_gaps() when a gap is confirmed to be
     * completely covered by retransmissions.
     */
    void register_filled_gaps(const std::vector<std::string>& packet_ids);

    /**
     * @brief Track that we observed a duplicate packet at @p seq for snapshot
     *        threshold evaluation.
     */
    void register_duplicate_snapshot(uint32_t seq);

    /// Evaluate whether the duplicate snapshot threshold has been exceeded.
    void evaluate_snapshot_duplicate_threshold();

    /// True if the per-snapshot duplicate threshold was exceeded for this flow.
    bool snapshot_duplicate_exceeded() const noexcept { return flow_snapshot_duplicate_exceeded_; }

    /// True if the per-snapshot out-of-order threshold was exceeded for this flow.
    bool snapshot_out_of_order_exceeded() const noexcept { return flow_snapshot_out_of_order_exceeded_; }

    // ---------------------------------------------------------------------
    // Hypothesis evaluation and flow-level decision
    // ---------------------------------------------------------------------

    /**
     * @brief Probability of the "closed-loop" hypothesis given the observed
     *        behaviour of this flow.
     */
    double hypothesis_closed_loop_probability() const noexcept;

    /**
     * @brief Probability of the "not closed-loop" hypothesis given the observed
     *        behaviour of this flow.
     */
    double hypothesis_not_closed_loop_probability() const noexcept;

    /**
     * @brief Check whether we have accumulated enough evidence to make a
     *        classification decision, and update final_decision() if so.
     */
    void evaluate_if_ready();

    // ---------------------------------------------------------------------
    // Drop decision and snapshot bookkeeping
    // ---------------------------------------------------------------------

    /**
     * @brief Decide whether to drop the packet carrying [start, end).
     *
     * @param start     Start sequence of the candidate drop.
     * @param end       End sequence of the candidate drop.
     * @param packet_id Logical identifier for this packet (used in snapshots).
     * @param key       Flow key associated with this packet.
     * @param now       Timestamp when the decision is made.
     *
     * @return true if the packet should be dropped, false otherwise.
     */
    bool drop_packet(uint32_t start,
                     uint32_t end,
                     const std::string& packet_id,
                     const FlowKey& key,
                     const std::chrono::steady_clock::time_point& now);

    /// Mark the snapshot associated with @p packet_id as retransmitted.
    void mark_snapshot_retransmitted(const std::string& packet_id);

    /// Mark the snapshot associated with @p packet_id as expired (no repair observed in time).
    void mark_snapshot_expired(const std::string& packet_id);

    /// Mark the snapshot associated with @p packet_id as invalid (e.g., misclassified or cancelled).
    void mark_snapshot_invalid(const std::string& packet_id);

    /// Mark all pending snapshots as expired (used on shutdown/cleanup).
    void expire_all_pending_snapshots();

private:
    /**
     * @brief Compute the final classification decision for this flow based on
     *        its current statistics and hypothesis probabilities.
     */
    FlowDecision evaluate() const;

    // ---------------------------------------------------------------------
    // Internal gap bookkeeping structures
    // ---------------------------------------------------------------------

    /**
     * @brief Internal record tying a dropped interval to its originating
     *        packet snapshot.
     *
     * interval_set cannot store per-interval metadata directly, so we track
     * a multimap keyed by starting sequence number.
     */
    struct GapRecord {
        icl::interval<uint32_t>::type range;  ///< Dropped byte range.
        std::string packet_id;               ///< Snapshot identifier.
        bool completed{false};               ///< True if the gap is fully repaired.
    };

    // ---------------------------------------------------------------------
    // Configuration and aggregated stats
    // ---------------------------------------------------------------------

    Config::ActiveConfig flow_cfg_{};  ///< Effective configuration for this flow.
    PennyStats flow_stats_{};         ///< Aggregated per-flow statistics.

    /// Total number of packets for which Penny enforced a drop.
    uint64_t flow_drops_enforced_{0};

    /// Last classification decision taken for this flow.
    FlowDecision flow_final_decision_{FlowDecision::PENDING};

    // ---------------------------------------------------------------------
    // Sequence / timing state
    // ---------------------------------------------------------------------

    bool flow_seen_syn_{false};            ///< True once we have observed the SYN.
    bool flow_has_seen_sequence_{false};   ///< True once we have observed any sequence-bearing packet.
    std::optional<std::chrono::steady_clock::time_point> flow_first_data_time_{};

    /// Mapping from snapshot packet_id to its index in flow_drop_snapshots_.
    std::unordered_map<std::string, size_t> flow_snapshot_index_by_id_;
    DropSnapshotSink drop_sink_{};

    /**
     * @brief Shared liveness flag observed by timer entries.
     *
     * Flipped to false in ~FlowEngine so timers can suppress callbacks for
     * flows that have already been destroyed.
     */
    std::shared_ptr<bool> flow_alive_flag_;

    // ---------------------------------------------------------------------
    // Drop snapshots and coverage / gap tracking
    // ---------------------------------------------------------------------

    /// Tracks whether a given packet_id was actually dropped.
    std::unordered_map<std::string, bool> flow_dropped_packets_;

    /// All packet-drop snapshots along with their logical packet_id.
    std::vector<std::pair<std::string, PacketDropSnapshot>> flow_drop_snapshots_;

    /// Bytes we have observed as covered in the sequence space.
    icl::interval_set<uint32_t> flow_covered_;

    /// Bytes we intentionally dropped (gaps yet to be repaired).
    icl::interval_set<uint32_t> flow_gaps_;

    /// Gap metadata keyed by starting sequence number.
    std::multimap<uint32_t, GapRecord> flow_gap_records_;

    /// Number of currently pending drops (not yet classified as repaired/expired).
    uint64_t flow_pending_drops_{0};

    /// Flags indicating whether thresholds were exceeded in the current snapshot window.
    bool flow_snapshot_duplicate_exceeded_{false};
    bool flow_snapshot_out_of_order_exceeded_{false};

    // ---------------------------------------------------------------------
    // Randomness for probabilistic dropping
    // ---------------------------------------------------------------------

    /// PRNG engine for stochastic drop decisions.
    std::mt19937 flow_random_engine_{std::random_device{}()};

    /// Uniform distribution in [0, 1) for drop probability sampling.
    std::uniform_real_distribution<double> flow_random_dist_{0.0, 1.0};

    // ---------------------------------------------------------------------
    // Flow identity
    // ---------------------------------------------------------------------

    FlowKey flow_key_{};  ///< 5-tuple (or equivalent) identifying this flow.
};

} // namespace openpenny::penny
