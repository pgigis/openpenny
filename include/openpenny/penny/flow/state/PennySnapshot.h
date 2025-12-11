// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/penny/flow/state/PennyStats.h"
#include <chrono>

namespace openpenny::penny {

/**
 * @brief Lifecycle state of a packet drop snapshot.
 *
 * Represents the status of a dropped packet as it moves through the Penny
 * decision process.
 */
enum class SnapshotState {
    Pending,        ///< Awaiting retransmission or expiry.
    Retransmitted,  ///< Observed retransmission that repairs the dropped range.
    Expired,        ///< No retransmission observed before the timeout.
    Invalid         ///< Snapshot was cancelled or deemed unusable.
};

/**
 * @brief Statistics snapshot captured when a packet drop is enforced.
 *
 * Records flow statistics at the time of a drop, along with a timestamp
 * and lifecycle state to support later evaluation and bookkeeping.
 */
struct PacketDropSnapshot {
    PennyStats stats{};  ///< Flow statistics at the moment of the packet drop.
    
    /// Wall clock time when the drop was recorded (monotonic steady clock).
    std::chrono::steady_clock::time_point timestamp{};
    
    /// Current lifecycle state of this snapshot.
    SnapshotState state{SnapshotState::Pending};
};

} // namespace openpenny::penny
