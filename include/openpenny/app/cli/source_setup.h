// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/app/cli/cli_helpers.h"

namespace openpenny::cli {

// Configure Config for the XDP path.
void configure_xdp_source(openpenny::Config& cfg, const CliOptions& opts);

// Configure Config for the DPDK path.
void configure_dpdk_source(openpenny::Config& cfg, const CliOptions& opts);

} // namespace openpenny::cli
