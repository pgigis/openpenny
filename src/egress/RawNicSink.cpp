// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file RawNicSink.cpp
 * @brief PacketSink that replays original Ethernet frames out a specific
 *        NIC using AF_PACKET/SOCK_RAW.
 *
 * Unlike RawSocketSink (IPPROTO_RAW), this sink does not ask the kernel
 * to route or ARP-resolve the packet. It transmits the captured layer-2
 * frame as-is on the selected NIC, so it is only correct when the
 * original Ethernet header is still valid on that egress segment.
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

int RawNicSink::open_socket_fd(bool resolve_ifindex, bool log_failures) {
    if (cfg_.device.empty()) {
        if (log_failures) {
            TCPLOG_ERROR("RawNicSink: device name is required%s", "");
        }
        return -1;
    }

    // SOCK_RAW (not SOCK_DGRAM): we want to forward the original frame
    // including its Ethernet header. SOCK_DGRAM strips L2 on RX and
    // synthesises one on TX from sockaddr_ll, but with no destination
    // MAC available the kernel sends the frame with an all-zero dst
    // MAC — which the next hop drops, so traffic never reaches its
    // destination. SOCK_RAW preserves the original L2 verbatim.
    //
    // ETH_P_ALL on the protocol so we can write any frame type.
    int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (fd < 0) {
        if (log_failures) {
            TCPLOG_ERROR("RawNicSink: socket(AF_PACKET, SOCK_RAW) failed: %s (need CAP_NET_RAW)",
                         std::strerror(errno));
        }
        return -1;
    }

    if (resolve_ifindex || if_index_ <= 0) {
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, cfg_.device.c_str(), IFNAMSIZ - 1);
        if (::ioctl(fd, SIOCGIFINDEX, &ifr) != 0) {
            const int saved = errno;
            if (log_failures) {
                TCPLOG_ERROR("RawNicSink: SIOCGIFINDEX('%s') failed: %s",
                             cfg_.device.c_str(), std::strerror(saved));
            }
            ::close(fd);
            errno = saved;
            return -1;
        }
        if_index_ = ifr.ifr_ifindex;
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_index_;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int saved = errno;
        if (log_failures) {
            TCPLOG_ERROR("RawNicSink: bind to '%s' (ifindex=%d) failed: %s",
                         cfg_.device.c_str(), if_index_, std::strerror(saved));
        }
        ::close(fd);
        errno = saved;
        return -1;
    }

    if (cfg_.raw_nic_bind_device) {
        if (::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                         cfg_.device.c_str(), cfg_.device.size()) != 0) {
            TCPLOG_WARN("RawNicSink: SO_BINDTODEVICE('%s') failed: %s",
                        cfg_.device.c_str(), std::strerror(errno));
        }
    }

    int sndbuf = 16 * 1024 * 1024;
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        TCPLOG_WARN("RawNicSink: SO_SNDBUF(%d) failed: %s",
                    sndbuf, std::strerror(errno));
    }

    return fd;
}

bool RawNicSink::open() {
    fd_ = open_socket_fd(true, true);
    if (fd_ < 0) {
        return false;
    }

    TCPLOG_INFO("RawNicSink: opened (fd=%d, device='%s', ifindex=%d)",
                fd_, cfg_.device.c_str(), if_index_);
    return true;
}

void RawNicSink::close() noexcept {
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
    if_index_ = -1;
}

int RawNicSink::thread_fd() {
    thread_local int t_fd = -1;
    thread_local const RawNicSink* t_owner = nullptr;
    if (t_owner == this && t_fd >= 0) {
        return t_fd;
    }
    if (fd_ < 0 || if_index_ <= 0) {
        t_owner = this;
        t_fd = -1;
        return t_fd;
    }

    int fd = open_socket_fd(false, false);
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

bool RawNicSink::write(const net::PacketView& packet) {
    const int fd = thread_fd();
    if (fd < 0) {
        return false;
    }

    // Preferred path: the source surfaced the original L2 frame, so we
    // can replay it verbatim through SOCK_RAW. The kernel doesn't add
    // any header — what we write goes on the wire as-is. This preserves
    // the original Ethernet src/dst MAC addresses, which is what makes
    // the next-hop switch / NIC accept the frame.
    const std::uint8_t* buf = nullptr;
    std::uint32_t       len = 0;
    if (packet.layer2_ptr && packet.layer2_length > 0) {
        buf = packet.layer2_ptr;
        len = packet.layer2_length;
    } else if (packet.layer3_ptr && packet.layer3_length > 0) {
        // Fallback: source has no L2 view (older readers, gRPC paths).
        // Sending bare L3 via SOCK_RAW would require us to fabricate an
        // Ethernet header, and we don't know the destination MAC. Warn
        // and drop to make this fail loudly rather than silently.
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true, std::memory_order_relaxed)) {
            TCPLOG_WARN("RawNicSink: source did not surface a layer-2 "
                        "frame; cannot forward via raw_nic without the "
                        "original Ethernet header. Use a different "
                        "egress kind (tun, raw_socket) or use a source "
                        "that populates packet.layer2_ptr.%s", "");
        }
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    } else {
        return false;
    }

    sockaddr_ll dst{};
    dst.sll_family = AF_PACKET;
    dst.sll_protocol = htons(ETH_P_ALL);
    dst.sll_ifindex = if_index_;

    const ssize_t written = ::sendto(fd,
                                     buf,
                                     static_cast<size_t>(len),
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
                "RawNicSink: TX backpressure on fd=%d (EAGAIN/EWOULDBLOCK); "
                "dropping packets. This can induce real TCP retransmissions at "
                "high rates because OpenPenny does not keep a copy-backed TX queue.",
                fd);
        }
        return false;
    }
    TCPLOG_WARN("RawNicSink::write (%u bytes) failed on fd=%d (device='%s'): %s",
                static_cast<unsigned>(len), fd,
                cfg_.device.c_str(), std::strerror(err));
    stats_.errors.fetch_add(1, std::memory_order_relaxed);
    return false;
}

std::string RawNicSink::describe() const {
    return "raw_nic://" + cfg_.device;
}

} // namespace openpenny::egress
