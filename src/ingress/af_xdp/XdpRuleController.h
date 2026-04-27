// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/net/TrafficMatch.h"

#include <cstdint>

namespace openpenny::xdp {

inline constexpr std::uint32_t kBpfMaxRules = 1;
inline constexpr std::uint32_t kBpfMatchRuleValueSize = 12 * sizeof(std::uint32_t);
inline constexpr std::uint32_t kBpfSettingsValueSize = 4 * sizeof(std::uint32_t);

struct XdpRuleMapFds {
    int rules_fd{-1};
    int settings_fd{-1};
};

bool program_xdp_match_rules(const XdpRuleMapFds& fds,
                             const net::TrafficMatchConfig& match_config,
                             unsigned queue,
                             bool drop_unmatched,
                             bool allow_ssh_bypass);

bool program_xdp_pass_defaults(const XdpRuleMapFds& fds,
                               bool allow_ssh_bypass);

} // namespace openpenny::xdp
