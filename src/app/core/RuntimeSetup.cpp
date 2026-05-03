// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/RuntimeSetup.h"

#include <atomic>

namespace openpenny {
namespace {
RuntimeSetupSnapshot g_runtime_setup;
std::atomic<bool> g_aggregates_active{true};
std::atomic<int> g_aggregates_status{
    static_cast<int>(RuntimeStatus::AggregatesStatus::PENDING)};
std::atomic<bool> g_has_aggregate_eval{false};
}

void set_runtime_setup(const Config& cfg,
                       const PipelineOptions& opts,
                       bool use_xdp,
                       bool use_dpdk) {
    g_runtime_setup.config = cfg;
    g_runtime_setup.options = opts;
    g_runtime_setup.use_xdp = use_xdp;
    g_runtime_setup.use_dpdk = use_dpdk;
    g_runtime_setup.aggregates_active = true;
    g_runtime_setup.testing_finished = false;
    g_runtime_setup.aggregates_status = RuntimeStatus::AggregatesStatus::PENDING;
    g_runtime_setup.aggregate_eval_counters = {};
    g_runtime_setup.has_aggregate_eval = false;
    g_aggregates_active.store(true, std::memory_order_release);
    g_aggregates_status.store(
        static_cast<int>(RuntimeStatus::AggregatesStatus::PENDING),
        std::memory_order_release);
    g_has_aggregate_eval.store(false, std::memory_order_release);
}

const RuntimeSetupSnapshot& current_runtime_setup() {
    return g_runtime_setup;
}

RuntimeSetupSnapshot& runtime_setup_mutable() {
    return g_runtime_setup;
}

bool current_aggregates_active() noexcept {
    return g_aggregates_active.load(std::memory_order_acquire);
}

void set_current_aggregates_active(bool value) noexcept {
    g_runtime_setup.aggregates_active = value;
    g_aggregates_active.store(value, std::memory_order_release);
}

RuntimeStatus::AggregatesStatus current_aggregates_status() noexcept {
    return static_cast<RuntimeStatus::AggregatesStatus>(
        g_aggregates_status.load(std::memory_order_acquire));
}

void set_current_aggregates_status(RuntimeStatus::AggregatesStatus status) noexcept {
    g_runtime_setup.aggregates_status = status;
    g_aggregates_status.store(static_cast<int>(status), std::memory_order_release);
}

bool current_has_aggregate_eval() noexcept {
    return g_has_aggregate_eval.load(std::memory_order_acquire);
}

void set_current_has_aggregate_eval(bool value) noexcept {
    g_runtime_setup.has_aggregate_eval = value;
    g_has_aggregate_eval.store(value, std::memory_order_release);
}

} // namespace openpenny
