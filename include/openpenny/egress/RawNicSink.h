// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file RawNicSink.h
 * @brief PacketSink implementation that replays original Ethernet frames
 *        out a specific NIC via AF_PACKET/SOCK_RAW.
 *
 * Unlike RawSocketSink (IPPROTO_RAW, which consults the routing table),
 * this sink transmits a captured layer-2 frame straight to a named
 * interface. It does not ARP / route / rewrite next-hop MAC addresses,
 * and it does not deliver packets into the local host stack. Use it only
 * when replaying the original Ethernet frame is actually valid for the
 * target egress segment.
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
