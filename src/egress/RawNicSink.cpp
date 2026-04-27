// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file RawNicSink.cpp
 * @brief PacketSink that emits IP datagrams out a specific NIC using
 *        an AF_PACKET/SOCK_DGRAM socket with a SOCK_DGRAM layer-3 view.
 *
 * AF_PACKET + SOCK_DGRAM lets us address the egress interface by
 * ifindex via sendto(2), bypassing the local routing table. That
 * matches operator intent when a named NIC is the desired egress
 * point -- IPPROTO_RAW (RawSocketSink) cannot make that guarantee
 * because routing still decides the output interface there.
 *
 * We write starting from the layer-3 header (IP); the kernel builds
 * the appropriate layer-2 encap from the socket's bind / sockaddr_ll.
 */

#include "openpenny/egress/RawNicSink.h"
#include "openpenny/net/Packet.h"
#include "openpenny/log/Log.h"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace openpenny::egress {

RawNicSink::RawNicSink(EgressConfig cfg) : cfg_(std::move(cfg)) {}

RawNicSink::~RawNicSink() {
    close();
}

bool RawNicSink::open() {
    if (cfg_.device.empty()) {
        TCPLOG_ERROR("RawNicSink: device name is required%s", "");
        return false;
    }

    fd_ = ::socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IP));
    if (fd_ < 0) {
        TCPLOG_ERROR("RawNicSink: socket(AF_PACKET, SOCK_DGRAM) failed: %s (need CAP_NET_RAW)",
                     std::strerror(errno));
        return false;
    }

    // Resolve ifindex once so the hot path doesn't need another syscall.
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, cfg_.device.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) != 0) {
        const int saved = errno;
        TCPLOG_ERROR("RawNicSink: SIOCGIFINDEX('%s') failed: %s",
                     cfg_.device.c_str(), std::strerror(saved));
        ::close(fd_);
        fd_ = -1;
        errno = saved;
        return false;
    }
    if_index_ = ifr.ifr_ifindex;

    // Bind to the interface so sendto(2) without a sockaddr works too, and
    // so the kernel drops incoming frames targeted at other ifaces.
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = if_index_;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int saved = errno;
        TCPLOG_ERROR("RawNicSink: bind to '%s' (ifindex=%d) failed: %s",
                     cfg_.device.c_str(), if_index_, std::strerror(saved));
        ::close(fd_);
        fd_ = -1;
        if_index_ = -1;
        errno = saved;
        return false;
    }

    if (cfg_.raw_nic_bind_device) {
        // Redundant with the bind() above on modern kernels, but harmless,
        // and it mirrors the IPPROTO_RAW path for consistency.
        if (::setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE,
                         cfg_.device.c_str(), cfg_.device.size()) != 0) {
            TCPLOG_WARN("RawNicSink: SO_BINDTODEVICE('%s') failed: %s",
                        cfg_.device.c_str(), std::strerror(errno));
        }
    }

    TCPLOG_INFO("RawNicSink: opened (fd=%d, device='%s', ifindex=%d)",
                fd_, cfg_.device.c_str(), if_index_);
    return true;
}

void RawNicSink::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if_index_ = -1;
}

bool RawNicSink::write(const net::PacketView& packet) {
    if (fd_ < 0 || !packet.layer3_ptr || packet.layer3_length == 0) {
        return false;
    }

    sockaddr_ll dst{};
    dst.sll_family = AF_PACKET;
    dst.sll_protocol = htons(ETH_P_IP);
    dst.sll_ifindex = if_index_;
    dst.sll_halen = ETH_ALEN; // Kernel will use interface default if unknown.
    // No sll_addr means "use the device's configured destination"; for
    // point-to-point NICs that's always correct. Operators wanting to
    // explicitly set a next-hop MAC should prefer a router upstream.

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
        TCPLOG_WARN("RawNicSink::write (%u bytes) failed on fd=%d (device='%s'): %s",
                    static_cast<unsigned>(packet.layer3_length), fd_,
                    cfg_.device.c_str(), std::strerror(err));
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
}

std::string RawNicSink::describe() const {
    return "raw_nic://" + cfg_.device;
}

} // namespace openpenny::egress
