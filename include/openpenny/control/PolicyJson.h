// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/control/Policy.h"

#include <nlohmann/json.hpp>

namespace openpenny::control {

nlohmann::json traffic_policy_to_json(const TrafficPolicy& policy);
nlohmann::json runtime_policy_to_json(const RuntimePolicy& policy);
nlohmann::json platform_config_to_json(const PlatformConfig& platform);
nlohmann::json desired_config_to_json(const DesiredConfig& desired,
                                      bool include_platform_details = false);
nlohmann::json effective_config_to_json(const EffectiveConfig& effective,
                                        bool include_platform_details = false);

} // namespace openpenny::control
