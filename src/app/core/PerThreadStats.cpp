// SPDX-License-Identifier: BSD-2-Clause

/**
 * @file PerThreadStats.cpp
 * @brief Provides thread local packet, byte, and flow counters, and exposes
 *        aggregated views across all active threads.
 *
 * Thread safety model:
 *   - Each thread operates on its own dedicated PerThreadStats instance.
 *   - Aggregation reads counters without locks; minor inconsistencies are tolerable
 *     because counters are monotonic and used for telemetry, not transactional state.
 *   - The system allows up to 128 independent counter slots to avoid contention.
 */

#include "openpenny/app/core/PerThreadStats.h"
#include <atomic>
#include <algorithm>

namespace openpenny::app {

namespace {

// Maximum number of per-thread counter slots.
constexpr std::size_t kMaxCounters = 128;

// Thread local index selecting which counter slot this thread writes to.
static thread_local std::size_t g_counter_index = 0;

// Static array holding counter objects, one per queue or thread.
static PerThreadStats g_counters[kMaxCounters]{};

// Defines how many counter slots are currently active. Atomic to allow
// safe updates when initialising systems with multiple queues.
static std::atomic<std::size_t> g_counters_size{1};

} // namespace

// -----------------------------------------------------------------------------
// Counter initialisation and assignment
// -----------------------------------------------------------------------------

/**
 * @brief Set the number of per-thread counters to initialise.
 *
 * This clamps the value to kMaxCounters and ensures at least one counter exists
 * so that single-queue execution paths remain valid.
 *
 * @param count Number of requested counters.
 */
void init_thread_counters(std::size_t count) {
    const auto clamped = std::min(count, kMaxCounters);
    
    // Ensure at least one counter slot is active.
    g_counters_size.store(
        clamped == 0 ? 1 : clamped,
        std::memory_order_relaxed
    );
}

/**
 * @brief Assign this thread to write to the counter slot @p idx.
 *
 * If the index is out of bounds, it is pinned to the final slot to ensure safety.
 *
 * @param idx The counter index this thread should use.
 */
void set_thread_counter_index(std::size_t idx) {
    if (idx >= kMaxCounters) {
        // Out of range index, use the final valid slot.
        g_counter_index = kMaxCounters - 1;
    } else {
        // Valid index within configured range.
        g_counter_index = idx;
    }
}

/**
 * @brief Retrieve the PerThreadStats instance bound to the current thread.
 *
 * If the thread was assigned a counter index beyond the currently active set size,
 * it is lazily corrected to stay within valid bounds.
 *
 * @return PerThreadStats reference for this thread's counters.
 */
PerThreadStats& current_thread_counters() {
    const auto size = g_counters_size.load(std::memory_order_relaxed);
    
    if (g_counter_index >= size) {
        // Thread index is stale, correct it to the final valid active counter.
        g_counter_index = size - 1;
    }

    return g_counters[g_counter_index];
}

// -----------------------------------------------------------------------------
// Counter views and aggregation
// -----------------------------------------------------------------------------

/**
 * @brief Returns a read-only snapshot view of all per-thread counters.
 *
 * This internally copies the currently active section of the static counter array
 * into a vector for external inspection. The returned reference remains valid until
 * the next call to this function.
 *
 * @return Vector view of all active PerThreadStats objects.
 */
const std::vector<PerThreadStats>& thread_counters() {
    static std::vector<PerThreadStats> view; // Rebuilt per call.
    const auto size = g_counters_size.load(std::memory_order_relaxed);

    // Create a copy so callers can iterate without touching static memory directly.
    view.assign(g_counters, g_counters + size);
    
    return view;
}

/**
 * @brief Fold all per-thread counters into a single monotonically growing total.
 *
 * This reads each PerThreadStats object from the static array and accumulates
 * all fields into an AggregatedCounters result structure.
 *
 * No locks are used because aggregation is telemetry-grade; some skew is allowed
 * but will never break correctness or safety guarantees.
 *
 * @return Single AggregatedCounters object representing all threads.
 */
AggregatedCounters aggregate_counters() {
    AggregatedCounters total;

    // Take a relaxed atomic snapshot of active threads.
    const auto size = g_counters_size.load(std::memory_order_relaxed);
    
    for (std::size_t i = 0; i < size; ++i) {
        const auto& c = g_counters[i];

        // Sum all counters across threads.
        total.packets                      += c.packets;
        total.bytes                        += c.bytes;
        total.errors                       += c.errors;
        total.flows_monitored              += c.flows_monitored;
        total.active_flows                 += c.active_flows;
        total.duplicate_packets             += c.duplicate_packets;
        total.droppable_packets             += c.droppable_packets;
        total.in_order_packets              += c.in_order_packets;
        total.out_of_order_packets          += c.out_of_order_packets;
        total.retransmitted_packets         += c.retransmitted_packets;
        total.non_retransmitted_packets     += c.non_retransmitted_packets;
        total.pending_retransmissions       += c.pending_retransmissions;
        total.dropped_packets               += c.dropped_packets;
        total.pure_ack_packets              += c.pure_ack_packets;
        total.data_packets                  += c.data_packets;
        total.flows_finished                += c.flows_finished;
        total.flows_rst                     += c.flows_rst;
        total.flows_closed_loop             += c.flows_closed_loop;
        total.flows_not_closed_loop         += c.flows_not_closed_loop;
        total.flows_duplicates_exceeded     += c.flows_duplicates_exceeded;
    }

    return total;
}

std::uint64_t aggregate_active_flows() {
    std::uint64_t total = 0;
    const auto size = g_counters_size.load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < size; ++i) {
        total += g_counters[i].active_flows;
    }
    return total;
}

} // namespace openpenny::app
