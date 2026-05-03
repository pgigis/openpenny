// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"

namespace openpenny {

// Store the current runtime setup so worker threads and helpers can inspect/update it.
void set_runtime_setup(const Config& cfg,
                       const PipelineOptions& opts,
                       bool use_xdp,
                       bool use_dpdk);

// Read-only view of the current runtime snapshot.
const RuntimeSetupSnapshot& current_runtime_setup();

// Mutable view for helpers that need to update status fields.
RuntimeSetupSnapshot& runtime_setup_mutable();

bool current_aggregates_active() noexcept;
void set_current_aggregates_active(bool value) noexcept;

RuntimeStatus::AggregatesStatus current_aggregates_status() noexcept;
void set_current_aggregates_status(RuntimeStatus::AggregatesStatus status) noexcept;

bool current_has_aggregate_eval() noexcept;
void set_current_has_aggregate_eval(bool value) noexcept;

} // namespace openpenny
