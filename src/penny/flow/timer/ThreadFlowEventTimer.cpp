// SPDX-License-Identifier: BSD-2-Clause

/**
 * @file ThreadFlowEventTimer.cpp
 * @brief Thread safe timer manager for handling packet drop related events
 *        including expiration, retransmission, and duplicate detection.
 *
 * Design principles:
 *   1. Expirations are prioritised to ensure snapshots age out promptly.
 *   2. Flow mutation never happens while holding internal locks.
 *   3. All callbacks execute in the timer thread itself to avoid
 *      cross-thread data races.
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

std::function<void(FlowEngine*, const std::string&, ThreadFlowEventTimerManager::SnapshotEventKind)>
    ThreadFlowEventTimerManager::snapshot_hook_{};

ThreadFlowEventTimerManager::~ThreadFlowEventTimerManager() {
    stop(); // Ensure the timer thread is terminated cleanly.
}

// -----------------------------------------------------------------------------
// Timer lifecycle management
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::start(double timeout_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    timeout_sec_ = timeout_sec;

    if (running_) return; // Prevent multiple timer threads from starting.

    stop_flag_ = false;
    running_ = true;
    thread_ = std::thread(&ThreadFlowEventTimerManager::timer_loop, this); // Spawn background timer loop.
}

void ThreadFlowEventTimerManager::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) return; // No action needed if thread is not running.
        stop_flag_ = true;
    }

    cv_.notify_all(); // Wake sleeping thread so it can terminate.

    if (thread_.joinable()) {
        thread_.join(); // Wait for graceful thread shutdown.
    }

    // Reset all internal state after stopping.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
        heap_ = {};
        by_id_.clear();
        by_flow_.clear();
        cancelled_.clear();
        retransmit_seen_.clear();
        events_.clear();
        callbacks_.clear();
        next_token_ = 1;
    }
}

// -----------------------------------------------------------------------------
// Event scheduling (called from packet processing threads)
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::register_drop(const ::openpenny::FlowKey& key,
                                         const std::string& packet_id,
                                         std::chrono::steady_clock::time_point ts,
                                         std::shared_ptr<bool> flow_alive,
                                         FlowEngine* flow,
                                         std::size_t snapshot_index) {
    std::unique_lock<std::mutex> lock(mutex_);

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

    wake_locked(); // Wake timer thread to re-evaluate scheduling.
}

void ThreadFlowEventTimerManager::enqueue_retransmitted(const std::string& packet_id, FlowEngine* flow) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!flow) return;

    // Queue retransmission event for later servicing.
    events_.push_back(Event{Event::Kind::Retransmit, packet_id, flow, 0});

    wake_locked(); // Wake timer loop.
}

void ThreadFlowEventTimerManager::enqueue_duplicate(FlowEngine* flow, std::uint32_t seq, std::uint32_t payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!flow) return;

    // Queue duplicate detection event for later servicing.
    events_.push_back(Event{Event::Kind::Duplicate, {}, flow, seq, payload});

    wake_locked(); // Wake timer loop.
}

// -----------------------------------------------------------------------------
// Cleanup and cancellation
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::purge_flow(FlowEngine* flow) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!flow) return;

    // Cancel all pending expiry entries for this flow using their token IDs.
    auto range = by_flow_.equal_range(flow);
    for (auto it = range.first; it != range.second; ++it) {
        cancelled_.insert(it->second);
    }

    by_flow_.erase(flow); // Remove all tokens referencing flow.
    retransmit_seen_.erase(
        std::remove_if(retransmit_seen_.begin(),
                       retransmit_seen_.end(),
                       [flow](const PacketKey& k) { return k.flow == flow; }),
        retransmit_seen_.end()
    );

    // Remove pending callbacks that reference the purged flow.
    callbacks_.erase(
        std::remove_if(callbacks_.begin(), callbacks_.end(),
                       [flow](const Callback& cb) { return cb.flow == flow; }),
        callbacks_.end()
    );

    wake_locked(); // Wake timer loop to apply purge.
}

void ThreadFlowEventTimerManager::wake_locked() {
    cv_.notify_all(); // Wake timer thread (called while holding mutex_).
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
            if (snapshot_hook_) snapshot_hook_(cb.flow, cb.packet_id, SnapshotEventKind::Expire);
        }
        else if (cb.kind == Callback::Kind::Retransmit) {
            cb.flow->mark_snapshot_retransmitted(cb.packet_id);
            if (snapshot_hook_) snapshot_hook_(cb.flow, cb.packet_id, SnapshotEventKind::Retransmit);
        }
        else if (cb.kind == Callback::Kind::Duplicate) {
            cb.flow->register_duplicate_snapshot(cb.seq);
            cb.flow->evaluate_snapshot_duplicate_threshold();
            if (snapshot_hook_) snapshot_hook_(cb.flow, {}, SnapshotEventKind::Duplicate);
        }

        cb.flow->evaluate_if_ready(); // Re-check whether the flow now satisfies its scheduling thresholds.
    }
}

// -----------------------------------------------------------------------------
// Timer loop (long running background scheduling thread)
// -----------------------------------------------------------------------------

void ThreadFlowEventTimerManager::timer_loop() {
    std::unique_lock<std::mutex> lock(mutex_);

    while (true) {
        if (stop_flag_) break; // Stop signal received.

        const auto now = std::chrono::steady_clock::now();

        // Remove stale cancelled entries at the top of the heap.
        while (!heap_.empty() && cancelled_.count(heap_.top().token)) {
            cancelled_.erase(heap_.top().token);
            heap_.pop();
        }

        bool processed_item = false;

        // 1) Process the next expiry if it is due.
        if (!heap_.empty() && now >= heap_.top().deadline) {
            auto entry = heap_.top();
            heap_.pop();

            // Remove entry from lookup maps if not already invalidated.
            auto id_it = by_id_.find(PacketKey{entry.flow, entry.packet_id});
            if (id_it != by_id_.end() && id_it->second.token == entry.token) {
                by_id_.erase(id_it);
            }

            // Remove only the token that matches this entry for the given flow.
            auto range = by_flow_.equal_range(entry.flow);
            for (auto it = range.first; it != range.second; ) {
                if (it->second == entry.token) {
                    it = by_flow_.erase(it);
                    break;
                } else {
                    ++it;
                }
            }

            // Ensure we only schedule snapshot mutation if the flow is still alive.
            if (auto alive = entry.flow_alive.lock(); alive && *alive && entry.flow) {
                if (TCPLOG_ENABLED(INFO)) {
                    TCPLOG_INFO("[packet_expired] flow=%s packet_id=%s token=%" PRIu64,
                        flow_debug_details(entry.flow->flow_key()).c_str(),
                        entry.packet_id.c_str(),
                        entry.token
                    );
                }

                // Schedule expiration callback for lock-free handling.
                callbacks_.push_back(Callback{
                    Callback::Kind::Expire, entry.packet_id, entry.flow, 0
                });
            }

            processed_item = true;
        }

        // 2) If no expiration was ready, service one queued event.
        else if (!events_.empty()) {
            auto ev = events_.front();
            events_.pop_front();

            if (ev.kind == Event::Kind::Retransmit && ev.flow) {
                auto it = by_id_.find(PacketKey{ev.flow, ev.packet_id});
                if (it != by_id_.end()) {
                    const auto token = it->second.token;

                    // Skip duplicate retransmit handling for the same flow/packet_id.
                    const PacketKey key{ev.flow, ev.packet_id};
                    if (std::find(retransmit_seen_.begin(), retransmit_seen_.end(), key) != retransmit_seen_.end()) {
                        processed_item = true;
                        continue;
                    }
                    retransmit_seen_.push_back(key);

                    // If we've already cancelled this token (due to an earlier
                    // retransmit event), skip duplicate handling/logging.
                    if (cancelled_.find(token) != cancelled_.end()) {
                        processed_item = true;
                        continue;
                    }

                    cancelled_.insert(token);

                    if (TCPLOG_ENABLED(INFO)) {
                        TCPLOG_INFO("[packet_retransmitted] flow=%s packet_id=%s seq=%" PRIu32,
                            flow_debug_details(ev.flow->flow_key()).c_str(),
                            ev.packet_id.c_str(),
                            ev.seq
                        );
                    }

                    callbacks_.push_back(Callback{
                        Callback::Kind::Retransmit, ev.packet_id, it->second.flow, 0
                    });
                }
            }
            else if (ev.kind == Event::Kind::Duplicate && ev.flow) {
                if (TCPLOG_ENABLED(DEBUG)) {
                    TCPLOG_DEBUG("[duplicate_detected] flow=%s seq=%" PRIu32 " payload=%u",
                        flow_debug_details(ev.flow->flow_key()).c_str(),
                        ev.seq,
                        ev.payload);
                }

                callbacks_.push_back(Callback{
                    Callback::Kind::Duplicate, {}, ev.flow, ev.seq
                });
            }

            processed_item = true;
        }

        // 2.5) Run callbacks immediately if any were produced.
        if (processed_item && !callbacks_.empty()) {
            std::deque<Callback> pending;
            pending.swap(callbacks_); // Extract callbacks without copying.

            lock.unlock();
            run_callbacks(pending); // Execute snapshot mutations in lock-free mode.
            lock.lock();

            continue; // Re-evaluate loop state after callback execution.
        }

        if (processed_item) continue;

        // 3) No action needed right now: sleep until the next expiry or event wake.
        if (!heap_.empty() && timeout_sec_ > 0.0) {
            cv_.wait_until(lock, heap_.top().deadline, [&] {
                return stop_flag_ || !events_.empty();
            });
        } else {
            cv_.wait(lock, [&] {
                return stop_flag_ || !events_.empty() ||
                       (!heap_.empty() && timeout_sec_ > 0.0);
            });
        }
    }
}

void ThreadFlowEventTimerManager::drain_callbacks() {
    // Drain all pending snapshot mutation callbacks for immediate execution.
    std::deque<Callback> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending.swap(callbacks_);
    }
    run_callbacks(pending);
}

void ThreadFlowEventTimerManager::set_snapshot_hook(std::function<void(FlowEngine*,
                                                                       const std::string&,
                                                                       SnapshotEventKind)> hook) {
    snapshot_hook_ = std::move(hook);
}

} // namespace openpenny::penny
