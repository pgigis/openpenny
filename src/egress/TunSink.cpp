// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file TunSink.cpp
 * @brief Implementation of the TUN-backed PacketSink.
 *
 * Canonical version replacing the duplicated open_tun_device() helpers
 * that used to live in penny_cli.cpp and penny_worker.cpp. Always
 * brings the interface administratively UP -- missing that step caused
 * the worker variant to silently black-hole every forwarded packet.
 */

#include "openpenny/egress/TunSink.h"
#include "openpenny/net/Packet.h"
#include "openpenny/log/Log.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace openpenny::egress {
namespace {

/**
 * @brief Write a single byte string to a /proc/sys sysctl entry.
 *
 * Returns true on success, false on any error. Errors are logged at WARN;
 * sysctl writes are best-effort because the kernel sometimes locks a subset
 * behind CAP_NET_ADMIN or per-namespace policy.
 */
bool write_proc_sys(const std::string& path, const char* value) {
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) {
        TCPLOG_WARN("TunSink: failed to open %s: %s",
                    path.c_str(), std::strerror(errno));
        return false;
    }
    const size_t len = std::strlen(value);
    const size_t written = std::fwrite(value, 1, len, f);
    const int close_rc = std::fclose(f);
    if (written != len || close_rc != 0) {
        TCPLOG_WARN("TunSink: short write to %s (%zu/%zu, close_rc=%d): %s",
                    path.c_str(), written, len, close_rc,
                    std::strerror(errno));
        return false;
    }
    return true;
}

} // namespace

TunSink::TunSink(EgressConfig cfg) : cfg_(std::move(cfg)) {}

TunSink::~TunSink() {
    close();
}

/**
 * @brief Configure the TUN interface: tx queue length, MTU, admin UP.
 *
 * Missing the IFF_UP step used to be silent murder: writes to a DOWN
 * interface succeed at the syscall boundary (the TUN fd accepts the
 * bytes) but the kernel immediately drops the packet before it reaches
 * the routing layer, so "packets forwarded but never reach destination"
 * is exactly what the operator sees. We always bring the interface up,
 * and log loudly if any ioctl fails.
 */
bool TunSink::tune_link(const std::string& name) const {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        TCPLOG_ERROR("Failed to open AF_INET socket to configure TUN '%s': %s",
                     name.c_str(), std::strerror(errno));
        return false;
    }

    bool ok = true;
    ifreq ifr{};

    // Deep TX queue so bursts from the XDP path don't dump into a 1k ring.
    if (cfg_.tun_txqlen > 0) {
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_qlen = cfg_.tun_txqlen;
        if (::ioctl(s, SIOCSIFTXQLEN, &ifr) != 0) {
            TCPLOG_WARN("SIOCSIFTXQLEN on TUN '%s' failed: %s",
                        name.c_str(), std::strerror(errno));
            ok = false;
        }
    }

    // Jumbo MTU so we can re-inject large frames without fragmenting.
    if (cfg_.tun_mtu > 0) {
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_mtu = cfg_.tun_mtu;
        if (::ioctl(s, SIOCSIFMTU, &ifr) != 0) {
            TCPLOG_WARN("SIOCSIFMTU on TUN '%s' (%d) failed: %s",
                        name.c_str(), ifr.ifr_mtu, std::strerror(errno));
            ok = false;
        }
    }

    // Bring the interface administratively UP. Without this step writes
    // to the TUN fd silently black-hole.
    if (cfg_.tun_bring_up) {
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            if ((ifr.ifr_flags & IFF_UP) == 0) {
                ifr.ifr_flags |= IFF_UP;
                if (::ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
                    TCPLOG_ERROR("SIOCSIFFLAGS UP on TUN '%s' failed: %s "
                                 "(forwarded packets will be silently dropped!)",
                                 name.c_str(), std::strerror(errno));
                    ok = false;
                }
            }
        } else {
            TCPLOG_ERROR("SIOCGIFFLAGS on TUN '%s' failed: %s",
                         name.c_str(), std::strerror(errno));
            ok = false;
        }
    }

    ::close(s);

    // Loose reverse-path filtering on the TUN so reinjected packets with
    // remote source IPs actually make it to the local socket. Without this,
    // strict rp_filter (the default on many distros) silently drops them
    // because the return route lives on the physical NIC, not the TUN.
    //
    // Note: rp_filter takes the MAX of conf/all/rp_filter and conf/<iface>/
    // rp_filter. Setting the interface to 2 overrides a strict (=1) global.
    if (cfg_.tun_rp_filter_loose) {
        const std::string iface_path =
            "/proc/sys/net/ipv4/conf/" + name + "/rp_filter";
        if (!write_proc_sys(iface_path, "2")) {
            TCPLOG_WARN("TunSink: could not set %s=2 "
                        "(reinjected packets may be dropped by strict rp_filter)",
                        iface_path.c_str());
        }
    }

    return ok;
}

bool TunSink::open() {
    if (cfg_.device.empty()) {
        TCPLOG_ERROR("TunSink: empty device name; refusing to open%s", "");
        return false;
    }

    fd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd_ < 0) {
        TCPLOG_ERROR("TunSink: open(/dev/net/tun) failed: %s", std::strerror(errno));
        return false;
    }

    auto try_attach = [&](short flags) -> bool {
        ifreq ifr{};
        ifr.ifr_flags = flags;
        std::strncpy(ifr.ifr_name, cfg_.device.c_str(), IFNAMSIZ - 1);
        return ::ioctl(fd_, TUNSETIFF, &ifr) == 0;
    };

    const short base_flags = IFF_TUN | IFF_NO_PI;
    bool attached = false;
    if (cfg_.tun_multi_queue) {
        attached = try_attach(base_flags | IFF_MULTI_QUEUE) || try_attach(base_flags);
    } else {
        attached = try_attach(base_flags);
    }
    if (!attached) {
        const int saved = errno;
        TCPLOG_ERROR("TunSink: TUNSETIFF on '%s' failed: %s",
                     cfg_.device.c_str(), std::strerror(saved));
        ::close(fd_);
        fd_ = -1;
        errno = saved;
        return false;
    }

    if (!tune_link(cfg_.device)) {
        const int saved = errno;
        ::close(fd_);
        fd_ = -1;
        errno = saved;
        return false;
    }

    TCPLOG_INFO("TunSink: opened '%s' (fd=%d, mtu=%d, multi_queue=%d, txqlen=%d)",
                cfg_.device.c_str(), fd_, cfg_.tun_mtu,
                cfg_.tun_multi_queue ? 1 : 0, cfg_.tun_txqlen);
    return true;
}

void TunSink::close() noexcept {
    // Close all extra per-thread fds first, then the master fd. We hold
    // fds_mtx_ briefly to safely empty the vector; per-thread cached
    // fds in `thread_fd()`'s thread_local will be re-opened (or fall
    // back to -1) if the sink is reused after this point.
    std::vector<int> to_close;
    {
        std::lock_guard<std::mutex> lock(fds_mtx_);
        to_close.swap(additional_fds_);
    }
    for (int fd : to_close) {
        if (fd >= 0) ::close(fd);
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// Per-thread TUN fd. With IFF_MULTI_QUEUE the kernel allows multiple fds
// to attach to the same TUN device, each backed by a separate internal
// queue. Without this, every worker calling ::write() on a single shared
// fd serialises on the device's queue lock — the dominant bottleneck
// for multi-queue AF_XDP runs reinjecting matched traffic.
//
// Cost model:
//   - first write() per worker: one open() + one ioctl(TUNSETIFF) + one
//     mutex acquire to register the fd in additional_fds_.
//   - subsequent writes: lock-free; the fd is cached in a thread_local.
int TunSink::thread_fd() {
    thread_local int t_fd = -1;
    thread_local const TunSink* t_owner = nullptr;
    if (t_owner == this && t_fd >= 0) {
        return t_fd;
    }

    // Single-queue TUN: only one fd is supported by the kernel; share
    // the master across writers. (Will still serialise; flagging
    // tun_multi_queue is the supported way to scale.)
    if (!cfg_.tun_multi_queue || fd_ < 0) {
        t_owner = this;
        t_fd = fd_;
        return t_fd;
    }

    int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        TCPLOG_WARN(
            "TunSink: failed to open per-worker queue fd (%s); "
            "falling back to shared master fd — expect contention "
            "with many workers",
            std::strerror(errno));
        t_owner = this;
        t_fd = fd_;
        return t_fd;
    }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    std::strncpy(ifr.ifr_name, cfg_.device.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, TUNSETIFF, &ifr) != 0) {
        TCPLOG_WARN(
            "TunSink: TUNSETIFF on per-worker queue fd for '%s' failed "
            "(%s); falling back to shared master fd",
            cfg_.device.c_str(), std::strerror(errno));
        ::close(fd);
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

bool TunSink::write(const net::PacketView& packet) {
    if (fd_ < 0 || !packet.layer3_ptr || packet.layer3_length == 0) {
        return false;
    }
    const int fd = thread_fd();
    const ssize_t written = ::write(fd, packet.layer3_ptr,
                                    static_cast<size_t>(packet.layer3_length));
    if (written >= 0) {
        stats_.forwarded.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    const int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK) {
        stats_.errors.fetch_add(1, std::memory_order_relaxed);
        if (!backpressure_logged_.exchange(true, std::memory_order_relaxed)) {
            TCPLOG_WARN(
                "TunSink: TX backpressure on fd=%d (EAGAIN/EWOULDBLOCK); "
                "dropping packets. This can induce real TCP retransmissions at "
                "high rates because OpenPenny does not keep a copy-backed TX queue.",
                fd);
        }
        return false;
    }
    TCPLOG_WARN("TunSink::write (%u bytes) failed on fd=%d: %s",
                static_cast<unsigned>(packet.layer3_length), fd,
                std::strerror(err));
    stats_.errors.fetch_add(1, std::memory_order_relaxed);
    return false;
}

std::string TunSink::describe() const {
    return "tun://" + cfg_.device;
}

} // namespace openpenny::egress
