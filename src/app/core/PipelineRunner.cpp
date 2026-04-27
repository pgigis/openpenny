// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/PipelineRunner.h"

#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/log/Log.h"

#include <cstdint>
#include <utility>

namespace openpenny {

PipelineRunner::PipelineRunner(const Config& cfg,
                               const PipelineOptions& opts,
                               FlowMatcher matcher,
                               net::PacketSourcePtr source,
                               IPipelineStrategy& strategy,
                               std::string thread_name)
    : cfg_(cfg),
      opts_(opts),
      matcher_(std::move(matcher)),
      source_(std::move(source)),
      strategy_(strategy),
      thread_name_(std::move(thread_name)) {}

std::optional<ModeResult> PipelineRunner::run() {
    if (!source_) {
        // Hardware or capture backend not configured or crashed.
        TCPLOG_ERROR("Packet source unavailable%s", "");
        return std::nullopt;
    }
    if (!source_->open(cfg_.ifname, cfg_.queue)) {
        TCPLOG_ERROR("Failed to open packet source on %s q%u",
                     cfg_.ifname.c_str(),
                     cfg_.queue);
        return std::nullopt;
    }

    strategy_.on_opened();

    ModeResult result{};
    bool poll_failed = false;

    // Compose the per-packet handler once. The runner owns the
    // "accept vs. drop" gate (matcher + should_stop) and the baseline
    // counter bumps; strategies see only packets they should act on.
    net::PacketHandler handler =
        [this, &result](const net::PacketView& packet) {
            if (opts_.should_stop && opts_.should_stop()) return;
            if (strategy_.filter_at_input() && matcher_ &&
                !matcher_(packet.flow)) {
                return;
            }

            ++result.packets_processed;
            auto& counters = openpenny::app::current_thread_counters();
            counters.packets += 1;
            counters.bytes +=
                static_cast<uint64_t>(packet.payload_bytes);

            const auto now = std::chrono::steady_clock::now();
            strategy_.on_packet(packet, now, result);
        };

    while (true) {
        strategy_.before_poll(std::chrono::steady_clock::now());
        if (strategy_.should_terminate()) break;
        if (opts_.should_stop && opts_.should_stop()) break;

        const auto before = result.packets_processed;
        if (!source_->poll(handler, strategy_.poll_budget())) {
            TCPLOG_ERROR("Packet poll failed%s", "");
            poll_failed = true;
            break;
        }
        const std::size_t processed_delta =
            result.packets_processed - before;
        strategy_.after_poll(std::chrono::steady_clock::now(),
                             processed_delta,
                             result);
        if (strategy_.should_terminate()) break;
    }

    strategy_.on_closing();
    source_->close();

    // Only promote strategy.penny_completed() into the result when we
    // exited cleanly; a poll failure leaves the flags at their
    // default-false so the driver can surface the fault.
    if (!poll_failed) {
        result.penny_completed = strategy_.penny_completed();
        result.aggregates_penny_completed = result.penny_completed;
    }
    strategy_.finalize(result);
    return result;
}

} // namespace openpenny
