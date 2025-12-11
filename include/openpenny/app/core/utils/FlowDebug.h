// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/Stats.h"

#include <string>
#include <cstdint>

namespace openpenny {

// Convert host-order IPv4 integer into dotted string for operator output.
std::string to_ipv4_string(uint32_t host_order_ip);

// Build a short tag describing a flow for logging.
std::string flow_debug_details(const FlowKey& flow);

} // namespace openpenny
