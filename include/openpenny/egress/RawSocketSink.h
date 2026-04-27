// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file RawSocketSink.h
 * @brief PacketSink implementation that writes layer-3 packets via a
 *        Linux IPPROTO_RAW socket (IP_HDRINCL=1).
 *
 * IPPROTO_RAW sockets take a complete IP datagram and drive the local
 * routing table to select an output interface, so SO_BINDTODEVICE is
 * only a hint. Use RawNicSink when bypassing the routing layer is
 * required.
 */

#include "openpenny/egress/PacketSink.h"

namespace openpenny::egress {

class RawSocketSink : public PacketSink {
public:
    explicit RawSocketSink(EgressConfig cfg);
    ~RawSocketSink() override;

    bool open() override;
    void close() noexcept override;
    bool write(const net::PacketView& packet) override;
    std::string describe() const override;
    EgressKind kind() const noexcept override { return EgressKind::RawSocket; }

private:
    EgressConfig cfg_{};
    int fd_ = -1;
};

} // namespace openpenny::egress
