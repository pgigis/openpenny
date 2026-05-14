// SPDX-License-Identifier: BSD-2-Clause
//
// Shared helpers for the tests under tests/unit/flow/.
//
// Goals:
// - Replace magic numbers (TCP flag bits, default 5-tuple values) with
//   named constants so a reader can tell intent at a glance.
// - Cut PacketView construction boilerplate to a single call.
// - Print a one-line banner per scenario so test output narrates itself
//   when a test fails or when running under `ctest --verbose`.
//
// All helpers are header-only and dependency-free beyond what the tests
// already include.

#pragma once

#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>

namespace openpenny::test {

// --- TCP flag bits ---------------------------------------------------------
inline constexpr std::uint8_t kTcpFin = 0x01;
inline constexpr std::uint8_t kTcpSyn = 0x02;
inline constexpr std::uint8_t kTcpRst = 0x04;
inline constexpr std::uint8_t kTcpPsh = 0x08;
inline constexpr std::uint8_t kTcpAck = 0x10;

// --- Default flow tuple ----------------------------------------------------
// A throwaway 5-tuple used by tests that only care about flow lifecycle,
// not packet routing. Override individual fields when a test pins down
// per-tuple behaviour.
inline FlowKey make_flow_key(std::uint32_t src_ip = 1,
                             std::uint32_t dst_ip = 2,
                             std::uint16_t src_port = 1000,
                             std::uint16_t dst_port = 2000,
                             std::uint8_t  ip_proto = 6 /* TCP */) {
    return FlowKey{src_ip, dst_ip, src_port, dst_port, ip_proto};
}

// --- PacketView construction ----------------------------------------------
// One-line builder. Defaults match a plain data packet of length 1.
// Pass flags = kTcpSyn (etc.) for handshakes; payload = 0 for pure ACKs.
inline net::PacketView make_packet(const FlowKey& flow,
                                   std::uint32_t  seq,
                                   std::uint64_t  payload = 1,
                                   std::uint8_t   flags   = 0) {
    net::PacketView pkt{};
    pkt.flow          = flow;
    pkt.tcp.seq       = seq;
    pkt.tcp.flags     = flags;
    pkt.payload_bytes = payload;
    return pkt;
}

// --- Scenario banner -------------------------------------------------------
// RAII helper. Constructing it prints "[test] scenario: <name>" so a
// failing assertion can be located by reading the test log; the
// destructor prints "[test]   ok: <name>" only when the scope exited
// without an unhandled exception (i.e. no assert tripped).
class Section {
public:
    explicit Section(std::string name)
        : name_(std::move(name)),
          uncaught_(std::uncaught_exceptions()) {
        std::cout << "scenario: " << name_ << '\n';
    }
    ~Section() {
        if (std::uncaught_exceptions() == uncaught_) {
            std::cout << "    ok:   " << name_ << '\n';
        }
    }
    Section(const Section&)            = delete;
    Section& operator=(const Section&) = delete;

private:
    std::string name_;
    int         uncaught_;
};

// --- Timer-singleton reset -------------------------------------------------
// The drop-timer singleton is shared across tests when the test binary
// runs multiple scenarios in one process. Call this at scenario
// boundaries (and at the start of main()) to avoid cross-pollution.
inline void reset_drop_timer() {
    penny::ThreadFlowEventTimerManager::instance().stop();
}

// --- Sleep helper ----------------------------------------------------------
inline void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

} // namespace openpenny::test
