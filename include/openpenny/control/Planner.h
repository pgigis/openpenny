// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/control/Policy.h"
#include "openpenny/net/TrafficMatch.h"

namespace openpenny::control {

net::TrafficMatchConfig compile_traffic_policy(const TrafficPolicy& policy);
CompiledRuntimeConfig compile_runtime_policy(const RuntimePolicy& policy);
CompiledDataplaneConfig compile_dataplane_config(const DesiredConfig& desired);
EffectiveConfig compile_effective_config(const DesiredConfig& desired);

DesiredConfig desired_from_legacy_config(const Config& cfg);
void apply_desired_config_to_legacy(Config& cfg, const DesiredConfig& desired);

} // namespace openpenny::control
