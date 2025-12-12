// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstdint>

namespace openpenny::app {
struct AggregatedCounters;
}

namespace openpenny::penny {

/**
 * @brief Statistics bundle tracking observable behaviour for a single TCP flow
 *        during Penny tests.
 *
 * These counters are used both by live flow instances and by snapshots captured
 * at the moment of packet drops, ensuring alignment of fields throughout the
 * decision process.
 *
 * This is a lightweight, copyable statistics container deliberately kept free of
 * locks because:
 *  1. It is written exclusively from the packet-processing thread.
 *  2. Snapshot reads occur after draining timer callbacks into the same thread.
 */
class PennyStats {
public:
    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /// Reset all counters to zero (keeps configuration untouched).
    void reset();

    // -------------------------------------------------------------------------
    // Packet event recording
    // -------------------------------------------------------------------------

    /// Record any observed packet belonging to this flow.
    void record_packet();

    /// Record a pure ACK packet (no TCP payload).
    void record_pure_ack();

    /// Record a packet that carries TCP payload.
    void record_data_packet();

    /// Record a packet that retransmits bytes already seen or already dropped.
    void record_duplicate_packet();

    /// Record a packet eligible for dropping according to the active policy.
    void record_droppable_packet();

    /// Record that Penny enforced a drop for a packet in this flow.
    void record_drop();

    // -------------------------------------------------------------------------
    // Retransmission bookkeeping
    // -------------------------------------------------------------------------

    /// Increase the count of pending retransmissions expected for repaired gaps.
    void inc_pending_retransmission();

    /// Decrease the count of pending retransmissions once a gap is repaired.
    void dec_pending_retransmission();

    /// Record that a retransmission repaired a previously dropped byte range.
    void inc_retransmitted();

    /// Record a sequence-bearing packet that is NOT a retransmission.
    void inc_non_retransmitted();

    /**
     * @brief Update ordering statistics based on a new sequence number.
     *
     * @param seq                The sequence number of the packet being processed.
     * @param has_seen_sequence  Whether the flow has already seen any sequence-bearing packet.
     * @return true if the packet is in-order, false if it is out-of-order.
     */
    bool track_ordering(uint32_t seq, bool has_seen_sequence);

    // -------------------------------------------------------------------------
    // Window maintenance and aggregation
    // -------------------------------------------------------------------------

    /**
     * @brief Clear temporary snapshot window counters (droppable, duplicate).
     *
     * These counters apply to a bounded snapshot window and should be reset after
     * each hypothesis evaluation cycle to avoid unbounded growth or double
     * counting across snapshots.
     */
    void clear_droppable_and_duplicates();

    /// Add all counters from @p other into this object.
    void add_from(const PennyStats& other);

    /// Subtract all counters in @p other from this object.
    void subtract_from(const PennyStats& other);

    /**
     * @brief Overwrite counters with aggregated values (where available).
     *
     * AggregatedCounters tracks packet-level counters but not highest_seq_,
     * so highest_seq_ is reset to zero here.
     */
    void overwrite_from_aggregates(const openpenny::app::AggregatedCounters& agg);

    // -------------------------------------------------------------------------
    // Accessors (read-only)
    // -------------------------------------------------------------------------

    uint64_t packets_seen() const noexcept { return packets_seen_; }
    uint64_t pure_ack_packets() const noexcept { return pure_ack_packets_; }
    uint64_t data_packets() const noexcept { return data_packets_; }
    uint64_t droppable_packets() const noexcept { return droppable_packets_; }
    uint64_t duplicate_packets() const noexcept { return duplicate_packets_; }
    uint64_t in_order_packets() const noexcept { return in_order_packets_; }
    uint64_t out_of_order_packets() const noexcept { return out_of_order_packets_; }
    uint64_t retransmitted_packets() const noexcept { return retransmitted_packets_; }
    uint64_t non_retransmitted_packets() const noexcept { return non_retransmitted_packets_; }
    uint64_t pending_retransmissions() const noexcept { return pending_retransmissions_; }
    uint64_t dropped_packets() const noexcept { return dropped_packets_; }

    /// Highest (normalised) sequence number seen for this flow.
    uint32_t highest_seq() const noexcept { return highest_seq_; }

    /// Set the highest sequence number; used after gap repairs extend coverage.
    void set_highest_seq(uint32_t seq) noexcept { highest_seq_ = seq; }

private:
    // Main per-flow counters (persist across the flow lifetime).
    uint64_t packets_seen_{0};
    uint64_t pure_ack_packets_{0};
    uint64_t data_packets_{0};
    uint64_t droppable_packets_{0};
    uint64_t duplicate_packets_{0};
    uint64_t in_order_packets_{0};
    uint64_t out_of_order_packets_{0};
    uint64_t retransmitted_packets_{0};
    uint64_t non_retransmitted_packets_{0};

    // Retransmission gap-repair counters.
    uint64_t pending_retransmissions_{0};
    uint64_t dropped_packets_{0};

    // Highest TCP sequence number observed (normalised).
    uint32_t highest_seq_{0};
};

} // namespace openpenny::penny
