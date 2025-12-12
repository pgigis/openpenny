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

} // namespace openpenny
