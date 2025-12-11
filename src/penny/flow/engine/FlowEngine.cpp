// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/engine/FlowEvaluation.h"
#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/log/Log.h"
#include "openpenny/app/core/utils/FlowDebug.h"

#include <algorithm>
#include <cinttypes>
#include <chrono>
#include <cmath>

namespace openpenny::penny {

FlowEngine::FlowEngine() : flow_alive_flag_(std::make_shared<bool>(true)) {}
FlowEngine::FlowEngine(const Config::ActiveConfig& cfg) : FlowEngine() { configure(cfg); }
FlowEngine::~FlowEngine() {
    if (flow_alive_flag_) {
        *flow_alive_flag_ = false;
    }
    ThreadFlowEventTimerManager::instance().purge_flow(this);
}

void FlowEngine::configure(const Config::ActiveConfig& cfg) {
    flow_cfg_ = cfg;
    reset();
    ThreadFlowEventTimerManager::instance().start(flow_cfg_.rtt_timeout_factor);
}

void FlowEngine::set_drop_sink(DropSnapshotSink sink) {
    drop_sink_ = std::move(sink);
}

void FlowEngine::reset() {
    ThreadFlowEventTimerManager::instance().purge_flow(this);
    flow_drops_enforced_ = 0;
    flow_stats_.reset();
    flow_seen_syn_ = false;
    flow_has_seen_sequence_ = false;
    flow_first_data_time_.reset();
    flow_final_decision_ = {};
    flow_covered_.clear();
    flow_gaps_.clear();
    flow_gap_records_.clear();
    flow_dropped_packets_.clear();
    flow_drop_snapshots_.clear();
    flow_pending_drops_ = 0;
    flow_snapshot_duplicate_exceeded_ = false;
    flow_snapshot_out_of_order_exceeded_ = false;
    flow_snapshot_index_by_id_.clear();
}

void FlowEngine::record_syn(uint32_t seq) {
    flow_seen_syn_ = true;
    flow_has_seen_sequence_ = true;
    flow_stats_.set_highest_seq(seq);
}

void FlowEngine::record_data(uint32_t seq, const std::chrono::steady_clock::time_point& ts) {
    if (!flow_first_data_time_) flow_first_data_time_ = ts;
    if (!flow_has_seen_sequence_ || seq > flow_stats_.highest_seq()) {
        flow_has_seen_sequence_ = true;
        flow_stats_.set_highest_seq(seq);
    }
}

void FlowEngine::record_packet() { flow_stats_.record_packet(); }

void FlowEngine::record_pure_ack() {
    flow_stats_.record_pure_ack();
    openpenny::app::current_thread_counters().pure_ack_packets++;
}

void FlowEngine::record_data_packet() {
    flow_stats_.record_data_packet();
    openpenny::app::current_thread_counters().data_packets++;
}

void FlowEngine::record_duplicate_packet() {
    flow_stats_.record_duplicate_packet();
    openpenny::app::current_thread_counters().duplicate_packets++;
}

void FlowEngine::record_droppable_packet() {
    flow_stats_.record_droppable_packet();
    openpenny::app::current_thread_counters().droppable_packets++;
}

// We maintain two disjoint interval sets:
//   1) flow_covered_ tracks every byte range we have already observed (sequence coverage).
//   2) flow_gaps_ stores byte ranges we intentionally dropped and expect to be refilled later.
// This split lets us quickly answer both "have we seen this data already?" and
// "did this retransmission repair an earlier drop?" without rescanning packets.
FlowEngine::IntervalMark FlowEngine::mark_interval(uint32_t start, uint32_t end) {
    IntervalMark mark{};
    mark.in_sequence = flow_stats_.track_ordering(start, flow_has_seen_sequence_);
    if (mark.in_sequence) {
        openpenny::app::current_thread_counters().in_order_packets++;
    } else {
        openpenny::app::current_thread_counters().out_of_order_packets++;
    }
    flow_has_seen_sequence_ = true;
    if (mark.in_sequence) {
        update_highest_sequence(end);
    }

    if (end <= start) end = start + 1; // Ensure right-open interval covers at least one byte.
    auto seg = icl::interval<uint32_t>::right_open(start, end); // [start, end) segment for this payload.
    bool duplicate = !icl::disjoint(flow_covered_, seg); // Overlap -> already seen some/all bytes.
    bool touches_gap = icl::intersects(flow_gaps_, seg);
    flow_covered_.add(seg); // Merge range into coverage tracker for future duplicate checks.
    mark.duplicate = duplicate;
    mark.touches_gap = touches_gap;
    return mark;
}

bool FlowEngine::track_ordering(uint32_t seq) {
    const bool in_order = flow_stats_.track_ordering(seq, flow_has_seen_sequence_);
    flow_has_seen_sequence_ = true;
    return in_order;
}

void FlowEngine::update_highest_sequence(uint32_t seq) {
    if (!flow_has_seen_sequence_ || seq > flow_stats_.highest_seq()) {
        flow_has_seen_sequence_ = true;
        flow_stats_.set_highest_seq(seq);
    }
}

// When we deliberately drop a packet range we record both the interval and the originating packet id,
// using the packet id as the unique drop identifier so filled gaps can find the matching drop snapshot
// and adjust counters once that specific drop is observed repaired.
void FlowEngine::register_gap(uint32_t start, uint32_t end, const std::string& packet_id) {
    if (end <= start) end = start + 1;
    auto seg = icl::interval<uint32_t>::right_open(start, end);
    flow_gaps_.add(seg);
    flow_gap_records_.emplace(start, GapRecord{seg, packet_id, false});
}

bool FlowEngine::fills_only_gap_space(uint32_t start, uint32_t end) const {
    if (end <= start) end = start + 1;
    auto seg = icl::interval<uint32_t>::right_open(start, end);
    return icl::contains(flow_gaps_, seg);
}

// fill_gaps
//   input: start/end byte positions of the retransmitted payload.
//   output: vector of packet ids whose entire dropped range has been recovered by this retransmission.
//   purpose: remove repaired regions from flow_gaps_ while pinpointing which previously dropped packets
//            have now been fully observed on the wire.
std::vector<std::string> FlowEngine::fill_gaps(uint32_t start, uint32_t end, bool* partially_filled) {
    std::vector<std::string> filled_ids;
    bool partial = false;
    if (end <= start) end = start + 1;
    auto seg = icl::interval<uint32_t>::right_open(start, end);
    if (!icl::intersects(flow_gaps_, seg)) {
        // Retransmission does not overlap any pending gap, so nothing to report.
        if (partially_filled) *partially_filled = false;
        return filled_ids;
    }

    // Track only the gap records that this retransmission touches; only those can transition to "filled".
    std::vector<GapRecord*> touched_records;
    if (!flow_gap_records_.empty()) {
        auto it = flow_gap_records_.lower_bound(start);
        // Step back to include any interval that begins before @start but overlaps it.
        while (it != flow_gap_records_.begin()) {
            auto prev = std::prev(it);
            if (icl::upper(prev->second.range) <= start) break;
            it = prev;
        }

        for (; it != flow_gap_records_.end(); ++it) {
            auto& record = it->second;
            if (record.completed) continue;
            if (!icl::intersects(record.range, seg)) {
                // Since the map is ordered by start, once we reach an interval that starts beyond @end
                // there can be no further overlaps.
                if (icl::lower(record.range) >= end) break;
                continue;
            }
            touched_records.push_back(&record);
        }
    }

    // Remove whatever portion we actually covered; remainder stays pending inside flow_gaps_.
    flow_gaps_.subtract(seg);

    // Any touched record whose interval no longer intersects the outstanding gaps has been completely repaired.
    for (auto* record : touched_records) {
        if (!record || record->completed) continue;
        bool still_missing = icl::intersects(flow_gaps_, record->range);
        if (still_missing) partial = true;
        if (!still_missing) {
            record->completed = true;
            filled_ids.push_back(record->packet_id);
        }
    }

    if (partially_filled) *partially_filled = partial;

    return filled_ids;
}

void FlowEngine::register_filled_gaps(const std::vector<std::string>& packet_ids) {
    if (packet_ids.empty()) return;
    for (const auto& id : packet_ids) {
        ThreadFlowEventTimerManager::instance().enqueue_retransmitted(id, this);
    }
}

void FlowEngine::register_duplicate_snapshot(uint32_t seq) {
    // Snanpshots are ordered by insertion; once we find the first snapshot whose coverage
    // includes this seq (highest_seq >= seq), all later snapshots should reflect the duplicate.
    bool update = false;
    for (size_t i = 0; i < flow_drop_snapshots_.size(); ++i) {
        auto& snap = flow_drop_snapshots_[i].second;
        if (!update && snap.stats.highest_seq() >= seq) {
            update = true;
        }
        if (update) {
            snap.stats.record_duplicate_packet();
        }
    }
}

void FlowEngine::evaluate_snapshot_duplicate_threshold() {
    if (flow_snapshot_duplicate_exceeded_) return;
    if (flow_cfg_.max_duplicate_fraction <= 0.0) return;
    const auto& snaps = flow_drop_snapshots_;
    for (const auto& snap_pair : snaps) {
        const auto& stats = snap_pair.second.stats;
        const auto data_pkts = stats.data_packets();
        if (data_pkts == 0) continue;
        double dup_ratio = static_cast<double>(stats.duplicate_packets()) /
                           static_cast<double>(data_pkts);
        if (dup_ratio > flow_cfg_.max_duplicate_fraction) {
            flow_snapshot_duplicate_exceeded_ = true;
            break;
        }
    }
}

bool FlowEngine::drop_packet(uint32_t start,
                            uint32_t end,
                            const std::string& packet_id,
                            const FlowKey& key,
                            const std::chrono::steady_clock::time_point& now) {

    // Check whether we have reached the maximum number of packet drops for this flow.
    const auto max_drops_per_flow = static_cast<uint64_t>(
        std::max(0, flow_cfg_.max_drops_per_indiv_flow)
    );

    if (max_drops_per_flow > 0 && flow_stats_.dropped_packets() >= max_drops_per_flow) {
        // The individual flow has hit its drop limit.
        return false;
    }

    // The second threshold applies globally across all flows (aggregated limit).
    const auto max_drops_in_aggregates = static_cast<uint64_t>(
        std::max(0, flow_cfg_.max_drops_aggregates)
    );

    if (max_drops_in_aggregates > 0) {
        const auto& runtime = openpenny::current_runtime_setup();
        if (runtime.aggregates_active) {
            auto agg = openpenny::app::aggregate_counters();
            if (agg.dropped_packets >= max_drops_in_aggregates) {
                // Global drop budget has been exhausted.
                return false;
            }
        }
    }
    
    // Decide whether to drop the packet, using the configured drop probability.
    double r = flow_random_dist_(flow_random_engine_); // Draw a uniform random number in [0, 1).
    bool should_drop = (r < flow_cfg_.drop_probability); // Check if it falls within the drop probability range.
    if (!should_drop) {
        // Do not drop this packet.
        return false;
    }

    // Record that this flow has one more retransmission outstanding and one more packet dropped.
    flow_stats_.inc_pending_retransmission();
    flow_stats_.record_drop();

    // Update the per-thread aggregate counter for pending retransmissions and dropped packets.
    {
        auto& stats = openpenny::app::current_thread_counters();
        stats.pending_retransmissions++;
        stats.dropped_packets++;
        stats.drop_snapshots.push_back(
            openpenny::app::PerThreadStats::DropSnapshotInfo{
                key,
                packet_id,
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        now.time_since_epoch()).count())
                ,
                flow_stats_.duplicate_packets(),
                flow_stats_.data_packets(),
                flow_stats_.retransmitted_packets(),
                flow_stats_.dropped_packets(),
                flow_stats_.pending_retransmissions()
            });
    }

    // Create a new packet drop snapshot.
    PacketDropSnapshot snap{flow_stats_, now, SnapshotState::Pending};

    if (drop_sink_) {
        drop_sink_(key, packet_id, snap);
    }
    
    flow_drop_snapshots_.emplace_back(packet_id, snap);
    const size_t snapshot_index = flow_drop_snapshots_.size() - 1;
    flow_snapshot_index_by_id_[packet_id] = snapshot_index;
    
    // Timer thread will later emit a callback (via ThreadFlowEventTimerManager) that we apply on this thread.
    ThreadFlowEventTimerManager::instance().register_drop(key, packet_id, snap.timestamp, flow_alive_flag_, this, snapshot_index);
    
    // Register the gap in the SEQ space.
    register_gap(start, end, packet_id);
    
    if (TCPLOG_ENABLED(INFO)) {
        const auto flow_tag = ::openpenny::flow_debug_details(key);
        TCPLOG_INFO(
            "[drop] flow=%s seq_range=%" PRIu32 "-%" PRIu32 " (len=%" PRIu32 ")",
            flow_tag.c_str(),
            start,
            end,
            end - start
        );
    }
    return true;
}

/**
 * Mark the drop snapshot associated with `packet_id` as retransmitted.
 *
 * This is called when we observe a retransmission for a previously dropped
 * packet that was still pending. We:
 *  - transition the snapshot state to `Retransmitted`,
 *  - update flow-wide and snapshot-local statistics,
 *  - propagate the "repair" outcome to later snapshots to keep counters
 *    consistent, and
 *  - remove the packet → snapshot index mapping.
 */
void FlowEngine::mark_snapshot_retransmitted(const std::string& packet_id) {
    // Look up the snapshot index by the packet ID.
    auto index_it = flow_snapshot_index_by_id_.find(packet_id);
    if (index_it == flow_snapshot_index_by_id_.end()) {
        return; // No snapshot tracked for this packet; nothing to update.
    }

    const auto idx = index_it->second;

    // Defensive bounds check to ensure the index is still valid.
    if (idx >= flow_drop_snapshots_.size()) {
        // Remove the entry to avoid repeated stale lookups.
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    auto& snapshot = flow_drop_snapshots_[idx].second;

    // Only snapshots in the Pending state should transition to Retransmitted.
    if (snapshot.state != SnapshotState::Pending) {
        // Do not override resolved snapshots; remove mapping and exit.
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    // Mark the snapshot as retransmitted: a repair occurred.
    snapshot.state = SnapshotState::Retransmitted;

    // Update flow-wide statistics.
    flow_stats_.inc_retransmitted();
    flow_stats_.dec_pending_retransmission();
    auto& counters = openpenny::app::current_thread_counters();
    counters.retransmitted_packets++;
    if (counters.pending_retransmissions > 0) counters.pending_retransmissions--;

    // Update snapshot-level statistics.
    snapshot.stats.dec_pending_retransmission();
    snapshot.stats.inc_retransmitted();

    // Propagate the repair outcome to later snapshots.
    //
    // Later snapshots may still count this packet as pending retransmission.
    // Now that we know it was repaired, adjust their counters to maintain
    // a consistent statistical view of the flow's history.
    for (std::size_t i = idx + 1; i < flow_drop_snapshots_.size(); ++i) {
        auto& later = flow_drop_snapshots_[i].second;

        // Only adjust counters if the later snapshot still considers this
        // packet pending. Resolved snapshots remain untouched.
        if (later.state == SnapshotState::Pending) {
            later.stats.dec_pending_retransmission();
            later.stats.inc_retransmitted();
        }
    }

    // Remove the packet → snapshot mapping; the snapshot is resolved.
    flow_snapshot_index_by_id_.erase(index_it);
}

/**
 * Mark the drop snapshot associated with `packet_id` as expired.
 *
 * This is called when we decide that a dropped packet was never retransmitted
 * within the expected time window. We:
 *  - mark the corresponding snapshot as Expired (if still Pending),
 *  - update flow-wide and snapshot-local statistics, and
 *  - propagate the outcome to any snapshots recorded after this one.
 */
void FlowEngine::mark_snapshot_expired(const std::string& packet_id) {
    // Look up the index of the snapshot associated with this packet ID.
    auto index_it = flow_snapshot_index_by_id_.find(packet_id);

    // If we do not have a snapshot for this packet, there is nothing to update.
    // This should be unusual; consider logging in debug builds.
    if (index_it == flow_snapshot_index_by_id_.end()) {
        return;
    }

    const auto idx = index_it->second;

    // Defensive check: ensure the stored index is still in range.
    if (idx >= flow_drop_snapshots_.size()) {
        // The mapping is stale; remove it to avoid repeated invalid lookups.
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    auto &snapshot = flow_drop_snapshots_[idx].second;

    // Only `Pending` snapshots can transition to `Expired`. If this snapshot
    // has already been resolved (e.g. marked as Retransmitted or already
    // Expired), do not override its outcome.
    if (snapshot.state != SnapshotState::Pending) {
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    // Mark this snapshot as expired: we never observed a retransmission
    // for the bytes covered by this drop.
    snapshot.state = SnapshotState::Expired;

    // Update flow-level statistics.
    flow_stats_.inc_non_retransmitted();
    flow_stats_.dec_pending_retransmission();
    auto& counters = openpenny::app::current_thread_counters();
    counters.non_retransmitted_packets++;
    if (counters.pending_retransmissions > 0) counters.pending_retransmissions--;

    // Update snapshot-local statistics.
    snapshot.stats.inc_non_retransmitted();
    snapshot.stats.dec_pending_retransmission();

    // Propagate the outcome to snapshots recorded after this one.
    //
    // Later snapshots may still be tracking this dropped packet as "pending
    // retransmission". Once we know the packet has expired, we need to update
    // their counters as well so their view remains consistent.
    for (std::size_t i = idx + 1; i < flow_drop_snapshots_.size(); ++i) {
        auto &later = flow_drop_snapshots_[i].second;

        // Only adjust counters for snapshots that still consider this packet
        // as pending; snapshots that have already been resolved should not be
        // touched.
        if (later.state == SnapshotState::Pending) {
            later.stats.dec_pending_retransmission();
            later.stats.inc_non_retransmitted();
        }
    }

    // We no longer need to look up this snapshot by packet ID.
    flow_snapshot_index_by_id_.erase(index_it);

    if (drop_sink_) {
        drop_sink_(flow_key_, packet_id, snapshot);
    }
}

/**
 * Mark the drop snapshot associated with `packet_id` as invalid.
 *
 * This is called when a previous packet drop should no longer be considered
 * for retransmission tracking (for example, it was a false positive or
 * overlapping with a resolved repair). We:
 *  - transition the snapshot state to `Invalid` (only if still pending),
 *  - decrement flow-wide and snapshot-local pending retransmission counters,
 *  - remove the packet → snapshot index mapping, and
 *  - ensure later snapshots no longer consider this packet as pending.
 */
void FlowEngine::mark_snapshot_invalid(const std::string& packet_id) {
    // Look up the index of the snapshot tracked for this packet.
    auto index_it = flow_snapshot_index_by_id_.find(packet_id);
    if (index_it == flow_snapshot_index_by_id_.end()) {
        return; // No snapshot exists for this packet; nothing to update.
    }

    const auto idx = index_it->second;

    // Defensive bounds check: ensure the mapped index refers to a valid snapshot.
    if (idx >= flow_drop_snapshots_.size()) {
        // The mapping is stale or corrupted; remove it to avoid repeat lookups.
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    auto& snapshot = flow_drop_snapshots_[idx].second;

    // Only Pending snapshots should transition to Invalid.
    // Already resolved snapshots must not be overridden.
    if (snapshot.state != SnapshotState::Pending) {
        // Snapshot already resolved; remove mapping and exit.
        flow_snapshot_index_by_id_.erase(index_it);
        return;
    }

    // Mark this snapshot as invalid: the packet drop is no longer tracked.
    snapshot.state = SnapshotState::Invalid;

    // Adjust snapshot-local pending retransmission statistics.
    snapshot.stats.dec_pending_retransmission();

    // Adjust flow-wide pending retransmission statistics.
    flow_stats_.dec_pending_retransmission();

    // Ensure snapshots recorded after this one remain statistically consistent.
    // They may still include this packet as pending, so remove that dependency.
    for (std::size_t i = idx + 1; i < flow_drop_snapshots_.size(); ++i) {
        auto& later = flow_drop_snapshots_[i].second;

        // Later snapshots should no longer track this packet as pending.
        // We adjust only their statistics, and do not assume anything about
        // their own resolution state.
        later.stats.dec_pending_retransmission();
    }

    // Remove the packet → snapshot index mapping; this snapshot is now resolved.
    flow_snapshot_index_by_id_.erase(index_it);
}

void FlowEngine::expire_all_pending_snapshots() {
    std::vector<std::string> pending_ids;
    pending_ids.reserve(flow_drop_snapshots_.size());
    for (const auto& pair : flow_drop_snapshots_) {
        if (pair.second.state == SnapshotState::Pending) {
            pending_ids.push_back(pair.first);
        }
    }
    for (const auto& id : pending_ids) {
        mark_snapshot_expired(id);
    }
}


FlowEngine::FlowDecision FlowEngine::evaluate() const {
    const auto eval = evaluate_flow_decision(
        flow_stats_,
        flow_cfg_.retransmission_miss_probability,
        flow_cfg_.max_duplicate_fraction);
    if (TCPLOG_ENABLED(INFO)) {
        const auto data_pkts        = flow_stats_.data_packets();
        const auto dup_pkts         = flow_stats_.duplicate_packets();
        const auto retransmitted    = flow_stats_.retransmitted_packets();
        const auto non_retransmitted= flow_stats_.non_retransmitted_packets();

        const double miss_prob = std::clamp(flow_cfg_.retransmission_miss_probability, 0.0, 1.0);

        const auto flow_tag = flow_debug_details(flow_key_);

        TCPLOG_INFO(
            "[flow_eval] flow=%s data_pkts=%llu dup_pkts=%llu rtx_pkts=%llu non_rtx_pkts=%llu "
            "dup_ratio=%.6f miss_prob=%.6f p_closed=%.6f p_not_closed=%.6f denom=%.6f closed_weight=%.6f",
            flow_tag.c_str(),
            static_cast<unsigned long long>(data_pkts),
            static_cast<unsigned long long>(dup_pkts),
            static_cast<unsigned long long>(retransmitted),
            static_cast<unsigned long long>(non_retransmitted),
            eval.dup_ratio,
            miss_prob,
            eval.p_closed,
            eval.p_not_closed,
            eval.p_closed + eval.p_not_closed,
            eval.closed_weight);
    }

    return eval.decision;
}

/**
 * Determine whether the flow has collected enough evidence to run the classifier.
 *
 * The flow is considered **ready for evaluation** only if:
 *   1. There are **no pending retransmissions** (all observed drops have been resolved), and
 *   2. The number of observed packet drops satisfies the configured thresholds:
 *        - If `max_drops_per_indiv_flow > 0`: require **exactly** that many drops.
 *        - If `max_drops_per_indiv_flow == 0`: require at least `min_drops_per_flow`.
 *
 * Once both conditions hold, we invoke `evaluate()` and store the result.
 */
void FlowEngine::evaluate_if_ready() {
    if (flow_final_decision_ != FlowDecision::PENDING) {
        return; // Decision already made; keep it.
    }

    // Do not evaluate if we have not observed any data packets; the classifier
    // requires data-bearing evidence.
    if (flow_stats_.data_packets() == 0) {
        return;
    }

    // Guard 1: the flow is not ready if any dropped packets are still awaiting retransmission.
    if (flow_stats_.pending_retransmissions() != 0) {
        return;
    }

    const auto exact_required_drops = static_cast<uint64_t>(
        std::max(0, flow_cfg_.max_drops_per_indiv_flow)
    );

    // Current number of packet drops recorded for this flow.
    const auto observed_drops = flow_stats_.dropped_packets();

    if (exact_required_drops > 0) {
        if (observed_drops != exact_required_drops) {
            return;
        }
    }

    // All readiness conditions are met: run the classifier and store the outcome.
    flow_final_decision_ = evaluate();
}

double FlowEngine::hypothesis_closed_loop_probability() const noexcept {
    // This estimates the probability that the flow is a **closed-loop**
    // (i.e. legitimate, non-spoofed) flow where retransmissions for dropped
    // packets were not observed **solely due to measurement blind spots**,
    // rather than because they never occurred.
    //
    // We model the chance of missing a single retransmission as
    // `retransmission_miss_probability` (clamped to [0,1]).
    // If we missed `N` non-retransmitted drops, and the misses were
    // independent, the probability they were all unobserved is `p^N`.

    const auto unobserved_drops = flow_stats_.non_retransmitted_packets();
    if (unobserved_drops == 0) {
        return 1.0; // No unobserved drops; fully consistent with a closed-loop flow.
    }

    const double p_miss = std::clamp(
        flow_cfg_.retransmission_miss_probability,
        0.0, 1.0
    );

    // Raise `p_miss` to the number of unobserved drops to obtain the final probability.
    return std::pow(p_miss, static_cast<double>(unobserved_drops));
}

double FlowEngine::hypothesis_not_closed_loop_probability() const noexcept {
    // This estimates the probability that the flow is **not** closed loop.
    //
    // A non–closed-loop flow should exhibit a high proportion of duplicate
    // packets relative to the total number of data packets (duplication ratio),
    // as well as repairs (retransmissions) of previously dropped sequence gaps.
    //
    // We model the duplication ratio as:
    //     dup_ratio = duplicate_data_packets / total_data_packets
    //
    // Assuming independence, and observing N retransmissions,
    // the probability the flow is not closed loop scales as:
    //     dup_ratio^N

    const auto total_data_packets = flow_stats_.data_packets();
    auto total_duplicate_packets = flow_stats_.duplicate_packets();

    if (total_duplicate_packets == 0) {
        // Keep duplication ratio minimally positive to avoid a zero probability outcome.
        // Must be always > 0.
        total_duplicate_packets = 1;
    }

    const double dup_ratio = static_cast<double>(total_duplicate_packets) /
                             static_cast<double>(total_data_packets);


    const auto total_retransmitted_packets = flow_stats_.retransmitted_packets();

    // If we have observed **no** retransmissions, and the duplication ratio is > 0,
    // we treat this as weak evidence for rejecting closed loop and return 1.0.
    if (total_retransmitted_packets == 0) {
        return 1.0;
    }

    // Raise the duplication ratio to the number of retransmissions to form
    // the final probability of the flow not being closed loop.
    return std::pow(dup_ratio, static_cast<double>(total_retransmitted_packets));
}

} // namespace openpenny::penny
