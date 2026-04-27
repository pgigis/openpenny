// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace openpenny {

/**
 * Matches a FlowKey against the active traffic policy. Returns true to
 * admit the flow into userspace processing, false to ignore.
 *
 * Historically declared in ActiveTestPipeline.h; moved here so active
 * and passive strategies can share it without one pulling in the
 * other's header.
 */
using FlowMatcher = std::function<bool(const FlowKey&)>;

/**
 * @brief Mode-specific hooks invoked by PipelineRunner.
 *
 * PipelineRunner owns the packet source lifecycle, the poll loop, the
 * per-thread counter bumps and the cooperative-cancellation check.
 * Anything that differs between active and passive traffic tests is
 * delegated to one of the virtual hooks below. The shared loop
 * guarantees a strict call order around each iteration:
 *
 *   before_poll(now)
 *   poll(handler, poll_budget())        // handler calls on_packet(...)
 *   after_poll(now, delta, result)
 *
 * The runner terminates when any of these fire:
 *   - opts.should_stop() returns true,
 *   - strategy.should_terminate() returns true (at iteration boundary),
 *   - the packet source reports a poll failure.
 */
class IPipelineStrategy {
public:
    virtual ~IPipelineStrategy() = default;

    /// Called exactly once, immediately after the packet source opens.
    virtual void on_opened() {}

    /// Called exactly once, immediately before the packet source closes.
    virtual void on_closing() {}

    /// Per-mode poll budget. 0 asks the source for its own default.
    virtual std::size_t poll_budget() const { return 0; }

    /**
     * Whether the runner applies the top-level FlowMatcher at ingress.
     *
     * Passive mode filters in userspace and returns true; active mode
     * relies on XDP/BPF filtering at the kernel and returns false.
     */
    virtual bool filter_at_input() const { return true; }

    /// Called once per poll iteration, just before source_->poll().
    virtual void before_poll(const std::chrono::steady_clock::time_point& now) {
        (void)now;
    }

    /**
     * Per-packet hook.
     *
     * Before this is called the runner has already:
     *   - bumped result.packets_processed,
     *   - bumped current_thread_counters().packets / .bytes,
     *   - filtered via matcher_ when filter_at_input() == true.
     *
     * The strategy decides when to forward via opts.sink and records
     * any mode-specific flow state.
     */
    virtual void on_packet(const net::PacketView& packet,
                           const std::chrono::steady_clock::time_point& now,
                           ModeResult& result) = 0;

    /**
     * Called once per poll iteration, immediately after source_->poll()
     * returns. Use this to expire idle flows, apply grace periods,
     * evaluate target-met stop conditions, etc.
     *
     * @param processed_delta  Packets delivered to on_packet() during
     *                         the poll that just finished.
     */
    virtual void after_poll(const std::chrono::steady_clock::time_point& now,
                            std::size_t processed_delta,
                            ModeResult& result) {
        (void)now;
        (void)processed_delta;
        (void)result;
    }

    /**
     * Additional stop condition beyond opts.should_stop(). Checked at
     * the top and bottom of every poll iteration.
     */
    virtual bool should_terminate() const { return false; }

    /// Whether the run completed the penny test successfully.
    virtual bool penny_completed() const { return false; }

    /**
     * Called once after the loop exits (graceful or poll-failure).
     * Strategies populate mode-specific ModeResult fields that the
     * shared runner doesn't know about.
     */
    virtual void finalize(ModeResult& result) {
        (void)result;
    }
};

/**
 * @brief Shared packet-processing skeleton.
 *
 * Owns:
 *   - the packet source lifecycle (open / close),
 *   - the poll loop with cooperative cancellation,
 *   - per-thread counter bumps (current_thread_counters),
 *   - base ModeResult totals (packets_processed, penny_completed).
 *
 * Mode-specific logic lives in an IPipelineStrategy passed by
 * reference. The strategy is not owned by the runner and must
 * outlive it.
 */
class PipelineRunner {
public:
    PipelineRunner(const Config& cfg,
                   const PipelineOptions& opts,
                   FlowMatcher matcher,
                   net::PacketSourcePtr source,
                   IPipelineStrategy& strategy,
                   std::string thread_name);

    /**
     * Drive the loop until a stop condition fires.
     *
     * @return nullopt when the source fails to open (caller treats this
     *         as the worker failing to start). On normal completion or
     *         mid-run poll failure returns a ModeResult populated with
     *         shared totals and whatever the strategy filled in via
     *         finalize().
     */
    std::optional<ModeResult> run();

private:
    const Config& cfg_;
    const PipelineOptions& opts_;
    FlowMatcher matcher_;
    net::PacketSourcePtr source_;
    IPipelineStrategy& strategy_;
    std::string thread_name_;
};

} // namespace openpenny
