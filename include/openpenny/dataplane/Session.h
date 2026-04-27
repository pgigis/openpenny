// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace openpenny::net {

struct PacketView;
struct TrafficMatchConfig;

using PacketHandler = std::function<void(const PacketView&)>;

} // namespace openpenny::net

namespace openpenny::dataplane {

/**
 * @brief Backend-neutral dataplane session used by Penny runtime code.
 *
 * Concrete AF_XDP/eBPF and DPDK implementations expose the same lifecycle:
 * open a queue on an interface, poll packets, and accept compiled match-rule
 * updates. Penny runtime code should depend on this interface rather than on
 * backend-specific reader classes.
 */
class Session {
public:
    virtual ~Session() = default;

    virtual bool open(const std::string& ifname, unsigned queue) = 0;
    virtual void close() = 0;
    virtual bool poll(const net::PacketHandler& handler, std::size_t budget = 32) = 0;
    virtual bool update_match_rules(const net::TrafficMatchConfig& config) {
        (void)config;
        return false;
    }
};

using SessionPtr = std::unique_ptr<Session>;

} // namespace openpenny::dataplane
