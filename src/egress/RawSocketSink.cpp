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

int RawSocketSink::open_socket_fd(bool log_failures) {
    int fd = ::socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
    if (fd < 0) {
        if (log_failures) {
            TCPLOG_ERROR("RawSocketSink: socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed: %s",
                         std::strerror(errno));
        }
        return -1;
    }

    if (!cfg_.device.empty()) {
        if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                         cfg_.device.c_str(), cfg_.device.size()) != 0) {
            const int saved = errno;
            TCPLOG_WARN("RawSocketSink: SO_BINDTODEVICE('%s') failed: %s",
                        cfg_.device.c_str(), std::strerror(saved));
        }
    }

    int one = 1;
    (void)::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int sndbuf = 16 * 1024 * 1024;
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        TCPLOG_WARN("RawSocketSink: SO_SNDBUF(%d) failed: %s",
                    sndbuf, std::strerror(errno));
    }

    return fd;
}

bool RawSocketSink::open() {
    fd_ = open_socket_fd(true);
    if (fd_ < 0) {
        return false;
    }

    TCPLOG_INFO("RawSocketSink: opened (fd=%d, device='%s')",
                fd_, cfg_.device.c_str());
    return true;
}

void RawSocketSink::close() noexcept {
    std::vector<int> to_close;
    {
        std::lock_guard<std::mutex> lock(fds_mtx_);
        to_close.swap(additional_fds_);
    }
    for (int fd : to_close) {
        if (fd >= 0) {
            ::close(fd);
        }
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int RawSocketSink::thread_fd() {
    thread_local int t_fd = -1;
    thread_local const RawSocketSink* t_owner = nullptr;
    if (t_owner == this && t_fd >= 0) {
        return t_fd;
    }
    if (fd_ < 0) {
        t_owner = this;
        t_fd = -1;
        return t_fd;
    }

    int fd = open_socket_fd(false);
    if (fd < 0) {
        t_owner = this;
        t_fd = fd_;
        return t_fd;
    }

    {
        std::lock_guard<std::mutex> lock(fds_mtx_);
        additional_fds_.push_back(fd);
    }
    t_owner = this;
    t_fd = fd;
    return t_fd;
}

bool RawSocketSink::write(const net::PacketView& packet) {
    if (!packet.layer3_ptr || packet.layer3_length < 20) {
        // IPv4 header is at least 20 bytes; anything shorter isn't a
        // routable datagram and the kernel would reject it anyway.
        return false;
    }
    const int fd = thread_fd();
    if (fd < 0) {
        return false;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    // Destination IP is at offset 16 in an IPv4 header; copy out-of-line
    // to respect alignment, even on architectures that can handle
    // unaligned loads.
    std::memcpy(&dst.sin_addr.s_addr, packet.layer3_ptr + 16,
                sizeof(dst.sin_addr.s_addr));

    const ssize_t written = ::sendto(fd,
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
    if (err == EAGAIN || err == EWOULDBLOCK) {
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
        if (!backpressure_logged_.exchange(true, std::memory_order_relaxed)) {
            TCPLOG_WARN(
                "RawSocketSink: TX backpressure on fd=%d (EAGAIN/EWOULDBLOCK); "
                "dropping packets. This can induce real TCP retransmissions at "
                "high rates because OpenPenny does not keep a copy-backed TX queue.",
                fd);
        }
        return false;
    }
    if (err == EMSGSIZE) {
        // The IP datagram is larger than the egress interface MTU.
        // IPPROTO_RAW with IP_HDRINCL cannot fragment for us, so this
        // is a hard "won't fit" result. Common on passive taps that
        // capture jumbo frames and try to forward them out a 1500-MTU
        // NIC. Log a single actionable hint, silently count the rest.
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
        bool expected = false;
        if (oversized_logged_.compare_exchange_strong(
                expected, true, std::memory_order_relaxed)) {
            TCPLOG_WARN(
                "RawSocketSink: dropped %u-byte IP datagram on fd=%d "
                "(EMSGSIZE) — packet exceeds the egress interface MTU "
                "and a raw socket cannot fragment. Either raise the "
                "egress MTU (e.g. `ip link set %s mtu %u`) or switch "
                "egress.kind to `tun`/`raw_nic` on a path that supports "
                "the packet size. Further oversized drops will be "
                "counted silently.",
                static_cast<unsigned>(packet.layer3_length),
                fd,
                cfg_.device.empty() ? "<egress-iface>" : cfg_.device.c_str(),
                static_cast<unsigned>(packet.layer3_length));
        }
        return false;
    }
    TCPLOG_WARN("RawSocketSink::write (%u bytes) failed on fd=%d: %s",
                static_cast<unsigned>(packet.layer3_length), fd,
                std::strerror(err));
    stats_.errors.fetch_add(1, std::memory_order_relaxed);
    return false;
}

std::string RawSocketSink::describe() const {
    std::string out = "raw_socket://";
    out += cfg_.device.empty() ? "<routed>" : cfg_.device;
    return out;
}

} // namespace openpenny::egress
