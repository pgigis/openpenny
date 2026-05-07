// SPDX-License-Identifier: BSD-2-Clause

/**
 * @file ThreadFlowEventTimer.cpp
 * @brief Per-thread timer manager for packet drop expiration,
 *        retransmission, and duplicate detection.
 *
 * Design principles:
 *   1. Expirations are prioritised to ensure snapshots age out promptly.
 *   2. The manager is strictly thread-local: every entry point goes
 *      through the static thread_local instance() returned below, so all
 *      members are touched by exactly one thread for the lifetime of that
 *      thread. This is what lets us run lock-free on the per-packet path
 *      — see the "Thread-local invariant" note in ThreadFlowEventTimer.h.
 *      An earlier implementation guarded each method with std::mutex; the
 *      mutex was uncontended by construction and was removed because the
 *      uncontended futex acquire+release was measurable hot-path overhead
 *      (~10-20ns per pair, multiplied by several calls per packet).
 *   3. All callbacks execute on the owning worker thread when it drains
 *      this manager, avoiding per-queue helper-thread context switches.
 *   4. Cancelled events are garbage collected lazily using a token heap.
 */

#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/log/Log.h"
#include "openpenny/app/core/utils/FlowDebug.h"

#include <algorithm>
#include <cinttypes>

namespace openpenny::penny {

// -----------------------------------------------------------------------------
// Singleton instance (one manager per thread)
// -----------------------------------------------------------------------------

ThreadFlowEventTimerManager& ThreadFlowEventTimerManager::instance() {
    static thread_local ThreadFlowEventTimerManager mgr; // Each thread gets its own local instance.
    return mgr;
}

ThreadFlowEventTimerManager::~ThreadFlowEventTimerManager() {
    stop(); // Ensure the worker-local timer state is flushed cleanly.
}

// -----------------------------------------------------------------------------
// Timer lifecycle management
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::start(double timeout_sec) {
    timeout_sec_ = timeout_sec;
    if (running_) return;
    running_ = true;
    next_deadline_ = kNoDeadline;
    queued_event_count_ = 0;
}

void ThreadFlowEventTimerManager::stop() {
    if (!running_) return;
    running_ = false;
    heap_ = {};
    by_id_.clear();
    by_flow_.clear();
    cancelled_.clear();
    retransmit_seen_.clear();
    events_.clear();
    queued_event_count_ = 0;
    next_deadline_ = kNoDeadline;
    next_token_ = 1;
}

// -----------------------------------------------------------------------------
// Event scheduling (called from packet processing threads)
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::register_drop(const ::openpenny::FlowKey& key,
                                         PacketDropId packet_id,
                                         std::chrono::steady_clock::time_point ts,
                                         std::shared_ptr<bool> flow_alive,
                                         FlowEngine* flow,
                                         std::size_t snapshot_index) {
    if (timeout_sec_ <= 0.0 || !flow) return; // Skip invalid registrations.

    // Prepare a new heap entry representing a packet snapshot timeout event.
    Entry e;
    e.token = next_token_++; // Unique cancellation token.
    // Cast to steady_clock::duration to avoid constructing a time_point with a double-based duration.
    e.deadline = ts + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                         std::chrono::duration<double>(timeout_sec_)); // Absolute timeout deadline.
    e.key = key;
    e.packet_id = packet_id;
    e.flow_alive = flow_alive;
    e.flow = flow;
    e.snapshot_index = snapshot_index;

    heap_.push(e); // Add to min-heap ordered by nearest expiry first.
    by_id_[PacketKey{flow, packet_id}] = e; // Register lookup by (flow, packet_id).
    by_flow_.emplace(flow, e.token); // Track token association to flow.
    const auto deadline = e.deadline.time_since_epoch().count();
    if (deadline < next_deadline_) {
        next_deadline_ = deadline;
    }
}

void ThreadFlowEventTimerManager::enqueue_retransmitted(PacketDropId packet_id, FlowEngine* flow) {
    if (!flow) return;

    // Queue retransmission event for later servicing.
    events_.push_back(Event{Event::Kind::Retransmit, packet_id, flow, 0});
    queued_event_count_ = events_.size();
}

void ThreadFlowEventTimerManager::enqueue_duplicate(FlowEngine* flow, std::uint32_t seq, std::uint32_t payload) {
    if (!flow) return;

    // Queue duplicate detection event for later servicing.
    events_.push_back(Event{Event::Kind::Duplicate, {}, flow, seq, payload});
    queued_event_count_ = events_.size();
}

// -----------------------------------------------------------------------------
// Cleanup and cancellation
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::purge_flow(FlowEngine* flow) {
    if (!flow) return;

    // Cancel all pending expiry entries for this flow using their token IDs.
    auto range = by_flow_.equal_range(flow);
    for (auto it = range.first; it != range.second; ++it) {
        cancelled_.insert(it->second);
    }

    by_flow_.erase(flow); // Remove all tokens referencing flow.
    for (auto it = retransmit_seen_.begin(); it != retransmit_seen_.end();) {
        if (it->flow == flow) {
            it = retransmit_seen_.erase(it);
        } else {
            ++it;
        }
    }
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
                       [flow](const Event& ev) { return ev.flow == flow; }),
        events_.end());
    queued_event_count_ = events_.size();
    refresh_next_deadline_locked();
}

// -----------------------------------------------------------------------------
// Callback execution (safe: runs without locks)
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::run_callbacks(std::deque<Callback>& pending) {
    for (auto& cb : pending) {
        if (!cb.flow) continue; // Skip invalid flows.

        // Dispatch callback by type (snapshot mutation).
        if (cb.kind == Callback::Kind::Expire) {
            cb.flow->mark_snapshot_expired(cb.packet_id);
        }
        else if (cb.kind == Callback::Kind::Retransmit) {
            cb.flow->mark_snapshot_retransmitted(cb.packet_id);
        }
        else if (cb.kind == Callback::Kind::Duplicate) {
            cb.flow->register_duplicate_snapshot(cb.seq);
            cb.flow->evaluate_snapshot_duplicate_threshold();
        }

        cb.flow->evaluate_if_ready(); // Re-check whether the flow now satisfies its scheduling thresholds.
    }
}

// Name retained as `_locked` for blame continuity / call-site readability,
// but no lock is held — the manager is thread-local. See header.
void ThreadFlowEventTimerManager::refresh_next_deadline_locked() {
    while (!heap_.empty() && cancelled_.count(heap_.top().token)) {
        cancelled_.erase(heap_.top().token);
        heap_.pop();
    }

    if (heap_.empty()) {
        next_deadline_ = kNoDeadline;
    } else {
        next_deadline_ = heap_.top().deadline.time_since_epoch().count();
    }
}

void ThreadFlowEventTimerManager::collect_ready_callbacks(
    std::deque<Callback>& pending,
    const std::chrono::steady_clock::time_point& now) {
    while (true) {
        refresh_next_deadline_locked();
        bool processed_item = false;

        if (!heap_.empty() && now >= heap_.top().deadline) {
            auto entry = heap_.top();
            heap_.pop();

            auto id_it = by_id_.find(PacketKey{entry.flow, entry.packet_id});
            if (id_it != by_id_.end() && id_it->second.token == entry.token) {
                by_id_.erase(id_it);
            }

            auto range = by_flow_.equal_range(entry.flow);
            for (auto it = range.first; it != range.second;) {
                if (it->second == entry.token) {
                    it = by_flow_.erase(it);
                    break;
                } else {
                    ++it;
                }
            }

            if (auto alive = entry.flow_alive.lock(); alive && *alive && entry.flow) {
                if (TCPLOG_ENABLED(INFO)) {
                    const auto packet_id_text = format_packet_drop_id(entry.packet_id);
                    TCPLOG_INFO("[packet_expired] flow=%s packet_id=%s token=%" PRIu64,
                                flow_debug_details(entry.flow->flow_key()).c_str(),
                                packet_id_text.c_str(),
                                entry.token);
                }
                pending.push_back(
                    Callback{Callback::Kind::Expire, entry.packet_id, entry.flow, 0});
            }

            processed_item = true;
        } else if (!events_.empty()) {
            auto ev = events_.front();
            events_.pop_front();
            queued_event_count_ = events_.size();

            if (ev.kind == Event::Kind::Retransmit && ev.flow) {
                auto it = by_id_.find(PacketKey{ev.flow, ev.packet_id});
                if (it != by_id_.end()) {
                    const auto token = it->second.token;
                    const PacketKey key{ev.flow, ev.packet_id};
                    const auto [_, inserted] = retransmit_seen_.insert(key);
                    if (!inserted) {
                        processed_item = true;
                        continue;
                    }
                    if (cancelled_.find(token) != cancelled_.end()) {
                        processed_item = true;
                        continue;
                    }

                    cancelled_.insert(token);

                    if (TCPLOG_ENABLED(INFO)) {
                        const auto packet_id_text = format_packet_drop_id(ev.packet_id);
                        TCPLOG_INFO(
                            "[drop_event] action=retransmitted flow=%s packet_id=%s seq=%" PRIu32,
                            flow_debug_details(ev.flow->flow_key()).c_str(),
                            packet_id_text.c_str(),
                            ev.seq);
                    }

                    pending.push_back(
                        Callback{Callback::Kind::Retransmit, ev.packet_id, it->second.flow, 0});
                }
            } else if (ev.kind == Event::Kind::Duplicate && ev.flow) {
                if (TCPLOG_ENABLED(DEBUG)) {
                    TCPLOG_DEBUG("[duplicate_detected] flow=%s seq=%" PRIu32 " payload=%u",
                                 flow_debug_details(ev.flow->flow_key()).c_str(),
                                 ev.seq,
                                 ev.payload);
                }
                pending.push_back(Callback{Callback::Kind::Duplicate, {}, ev.flow, ev.seq});
            }

            processed_item = true;
        }

        if (!processed_item) {
            refresh_next_deadline_locked();
            return;
        }
    }
}

void ThreadFlowEventTimerManager::drain_callbacks() {
    const auto now = std::chrono::steady_clock::now();
    // Fast-path early-exit: cheap plain reads (manager is thread-local; see
    // header for the invariant). Used to be std::atomic loads back when this
    // peeked while a different thread held the mutex — neither matters now.
    if (queued_event_count_ == 0 &&
        (next_deadline_ == kNoDeadline ||
         now.time_since_epoch().count() < next_deadline_)) {
        return;
    }

    if (!running_) {
        return;
    }

    std::deque<Callback> pending;
    collect_ready_callbacks(pending, now);
    run_callbacks(pending);
}

} // namespace openpenny::penny
