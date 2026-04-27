// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/control/Policy.h"

namespace openpenny::control {

const char* to_string(TrafficDecision decision) noexcept {
    switch (decision) {
    case TrafficDecision::Include: return "include";
    case TrafficDecision::Exclude: return "exclude";
    }
    return "unknown";
}

const char* to_string(RuntimeMode mode) noexcept {
    switch (mode) {
    case RuntimeMode::Active: return "active";
    case RuntimeMode::Passive: return "passive";
    }
    return "unknown";
}

const char* to_string(PlatformBackend backend) noexcept {
    switch (backend) {
    case PlatformBackend::AfXdp: return "af_xdp";
    case PlatformBackend::Dpdk: return "dpdk";
    }
    return "unknown";
}

} // namespace openpenny::control
