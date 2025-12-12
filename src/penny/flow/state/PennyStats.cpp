// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/penny/flow/state/PennyStats.h"
#include "openpenny/app/core/PerThreadStats.h"

namespace openpenny::penny {

void PennyStats::reset() {
    packets_seen_ = 0;
    pure_ack_packets_ = 0;
    data_packets_ = 0;
    droppable_packets_ = 0;
    duplicate_packets_ = 0;
    in_order_packets_ = 0;
    out_of_order_packets_ = 0;
    retransmitted_packets_ = 0;
    non_retransmitted_packets_ = 0;
    pending_retransmissions_ = 0;
    dropped_packets_ = 0;
    highest_seq_ = 0;
}

void PennyStats::record_packet() { ++packets_seen_; }

void PennyStats::record_pure_ack() {
    ++pure_ack_packets_;
    ++packets_seen_;
}

void PennyStats::record_data_packet() {
    ++data_packets_;
    ++packets_seen_;
}

void PennyStats::record_duplicate_packet() {
    ++duplicate_packets_;
    ++packets_seen_;
}

void PennyStats::record_droppable_packet() { ++droppable_packets_; }

void PennyStats::record_drop() { ++dropped_packets_; }

void PennyStats::inc_pending_retransmission() { ++pending_retransmissions_; }

void PennyStats::dec_pending_retransmission() {
    if (pending_retransmissions_ > 0) --pending_retransmissions_;
}

void PennyStats::inc_retransmitted() { ++retransmitted_packets_; }

void PennyStats::inc_non_retransmitted() { ++non_retransmitted_packets_; }

bool PennyStats::track_ordering(uint32_t seq, bool has_seen_sequence) {
    if (!has_seen_sequence) {
        highest_seq_ = seq;
        ++in_order_packets_;
        return true;
    }
    if (seq >= highest_seq_) {
        highest_seq_ = seq;
        ++in_order_packets_;
        return true;
    }
    ++out_of_order_packets_;
    return false;
}

void PennyStats::clear_droppable_and_duplicates() {
    droppable_packets_ = 0;
    duplicate_packets_ = 0;
}

void PennyStats::add_from(const PennyStats& other) {
    packets_seen_ += other.packets_seen_;
    pure_ack_packets_ += other.pure_ack_packets_;
    data_packets_ += other.data_packets_;
    droppable_packets_ += other.droppable_packets_;
    duplicate_packets_ += other.duplicate_packets_;
    in_order_packets_ += other.in_order_packets_;
    out_of_order_packets_ += other.out_of_order_packets_;
    retransmitted_packets_ += other.retransmitted_packets_;
    non_retransmitted_packets_ += other.non_retransmitted_packets_;
    pending_retransmissions_ += other.pending_retransmissions_;
    dropped_packets_ += other.dropped_packets_;
    if (other.highest_seq_ > highest_seq_) highest_seq_ = other.highest_seq_;
}

void PennyStats::subtract_from(const PennyStats& other) {
    auto sub = [](uint64_t& dest, uint64_t delta) {
        dest = (dest >= delta) ? (dest - delta) : 0;
    };
    sub(packets_seen_, other.packets_seen_);
    sub(pure_ack_packets_, other.pure_ack_packets_);
    sub(data_packets_, other.data_packets_);
    sub(droppable_packets_, other.droppable_packets_);
    sub(duplicate_packets_, other.duplicate_packets_);
    sub(in_order_packets_, other.in_order_packets_);
    sub(out_of_order_packets_, other.out_of_order_packets_);
    sub(retransmitted_packets_, other.retransmitted_packets_);
    sub(non_retransmitted_packets_, other.non_retransmitted_packets_);
    sub(pending_retransmissions_, other.pending_retransmissions_);
    sub(dropped_packets_, other.dropped_packets_);
    // highest_seq_ not decremented; it reflects max seen, not a sum.
}

void PennyStats::overwrite_from_aggregates(const openpenny::app::AggregatedCounters& agg) {
    // Aggregate totals; pure ACK/data breakdown and highest_seq_ are not available.
    packets_seen_            = agg.packets;
    droppable_packets_       = agg.droppable_packets;
    duplicate_packets_       = agg.duplicate_packets;
    in_order_packets_        = agg.in_order_packets;
    out_of_order_packets_    = agg.out_of_order_packets;
    retransmitted_packets_   = agg.retransmitted_packets;
    non_retransmitted_packets_= agg.non_retransmitted_packets;
    pending_retransmissions_ = agg.pending_retransmissions;
    dropped_packets_         = agg.dropped_packets;
    pure_ack_packets_        = agg.pure_ack_packets;
    data_packets_            = agg.data_packets;
    highest_seq_             = 0; // Aggregate does not track sequence maxima.
}

} // namespace openpenny::penny
