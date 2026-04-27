// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file RawNicSink.h
 * @brief PacketSink implementation that emits layer-3 packets out a
 *        specific NIC via an AF_PACKET/SOCK_DGRAM socket.
 *
 * Unlike RawSocketSink (IPPROTO_RAW, which consults the routing table),
 * this sink writes frames straight to a named interface using
 * AF_PACKET, making it appropriate for mirroring / reinjection
 * scenarios where the operator wants the traffic to leave a physical
 * port without being re-routed by the local host.
 */

#include "openpenny/egress/PacketSink.h"

namespace openpenny::egress {

class RawNicSink : public PacketSink {
public:
    explicit RawNicSink(EgressConfig cfg);
    ~RawNicSink() override;

    bool open() override;
    void close() noexcept override;
    bool write(const net::PacketView& packet) override;
    std::string describe() const override;
    EgressKind kind() const noexcept override { return EgressKind::RawNic; }

private:
    EgressConfig cfg_{};
    int fd_ = -1;
    int if_index_ = -1; ///< Cached ifindex for sendto(2).
};

} // namespace openpenny::egress
