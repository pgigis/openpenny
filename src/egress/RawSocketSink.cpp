// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file RawSocketSink.cpp
 * @brief PacketSink that writes IP datagrams to an IPPROTO_RAW socket.
 *
 * The kernel still consults the local routing table for packets written
 * to an IPPROTO_RAW socket; SO_BINDTODEVICE here is a hint to prefer
 * egress via `cfg.device` but does not bypass routing decisions.
 */

#include "openpenny/egress/RawSocketSink.h"
#include "openpenny/net/Packet.h"
#include "openpenny/log/Log.h"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace openpenny::egress {

RawSocketSink::RawSocketSink(EgressConfig cfg) : cfg_(std::move(cfg)) {}

RawSocketSink::~RawSocketSink() {
    close();
}

bool RawSocketSink::open() {
    fd_ = ::socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
    if (fd_ < 0) {
        TCPLOG_ERROR("RawSocketSink: socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed: %s",
                     std::strerror(errno));
        return false;
    }

    if (!cfg_.device.empty()) {
        if (::setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE,
                         cfg_.device.c_str(), cfg_.device.size()) != 0) {
            const int saved = errno;
            TCPLOG_WARN("RawSocketSink: SO_BINDTODEVICE('%s') failed: %s",
                        cfg_.device.c_str(), std::strerror(saved));
            // SO_BINDTODEVICE requires CAP_NET_RAW; treat as non-fatal so
            // the sink still works when the operator just hasn't named a
            // preferred egress device.
        }
    }

    // IPPROTO_RAW already implies IP_HDRINCL, but set it explicitly so the
    // behaviour is obvious to reviewers tracing packet construction.
    int one = 1;
    (void)::setsockopt(fd_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    TCPLOG_INFO("RawSocketSink: opened (fd=%d, device='%s')",
                fd_, cfg_.device.c_str());
    return true;
}

void RawSocketSink::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool RawSocketSink::write(const net::PacketView& packet) {
    if (fd_ < 0 || !packet.layer3_ptr || packet.layer3_length < 20) {
        // IPv4 header is at least 20 bytes; anything shorter isn't a
        // routable datagram and the kernel would reject it anyway.
        return false;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    // Destination IP is at offset 16 in an IPv4 header; copy out-of-line
    // to respect alignment, even on architectures that can handle
    // unaligned loads.
    std::memcpy(&dst.sin_addr.s_addr, packet.layer3_ptr + 16,
                sizeof(dst.sin_addr.s_addr));

    const ssize_t written = ::sendto(fd_,
                                     packet.layer3_ptr,
                                     static_cast<size_t>(packet.layer3_length),
                                     0,
                                     reinterpret_cast<sockaddr*>(&dst),
                                     sizeof(dst));
    if (written >= 0) {
        stats_.forwarded.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    const int err = errno;
    if (err != EAGAIN && err != EWOULDBLOCK) {
        TCPLOG_WARN("RawSocketSink::write (%u bytes) failed on fd=%d: %s",
                    static_cast<unsigned>(packet.layer3_length), fd_,
                    std::strerror(err));
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
}

std::string RawSocketSink::describe() const {
    std::string out = "raw_socket://";
    out += cfg_.device.empty() ? "<routed>" : cfg_.device;
    return out;
}

} // namespace openpenny::egress
