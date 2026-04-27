// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file AfPacketMirrorReader.cpp
 * @brief Implementation of the AF_PACKET-based passive mirror reader.
 *
 * The reader is a thin wrapper around a packet socket bound to a single
 * interface via `sockaddr_ll`. `PACKET_OUTGOING` frames are filtered out
 * by default so we only see ingress. All higher-level filtering lives in
 * userspace (the shared `TrafficMatchConfig`) to keep the MVP simple and
 * leave room for a future kernel-side cBPF fast path.
 */

#include "openpenny/ingress/af_packet/AfPacketMirrorReader.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"
#include "openpenny/net/TrafficMatch.h"

#include <cerrno>
#include <chrono>
#include <cstring>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace openpenny::ingress::af_packet {

namespace {

constexpr std::size_t kMinFrameBuf = 2048;
constexpr std::size_t kDefaultFrameBuf = 9216; // Jumbo + headroom.

std::uint64_t now_nanos() noexcept {
    using clock = std::chrono::steady_clock;
    const auto d = clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
}

/// Resolve an interface name to its kernel ifindex.
unsigned resolve_ifindex(const std::string& ifname) noexcept {
    if (ifname.empty()) return 0;
    return if_nametoindex(ifname.c_str());
}

} // namespace

AfPacketMirrorReader::AfPacketMirrorReader() = default;

AfPacketMirrorReader::~AfPacketMirrorReader() {
    AfPacketMirrorReader::close();
}

void AfPacketMirrorReader::configure(const Options& opts) {
    opts_ = opts;
    if (opts_.frame_size < kMinFrameBuf) {
        opts_.frame_size = kDefaultFrameBuf;
    }
    frame_buf_.assign(opts_.frame_size, 0);
}

void AfPacketMirrorReader::configure_from_config(const Config& cfg) {
    Options o;
    o.batch           = cfg.xdp_runtime.batch > 0 ? cfg.xdp_runtime.batch : 256;
    o.poll_timeout_ms = static_cast<int>(cfg.xdp_runtime.poll_timeout_ms);
    // Prefer a generous buffer; the AF_PACKET ring has no zero-copy path so
    // copies dominate and larger frames reduce syscall overhead on jumbos.
    o.frame_size      = cfg.frame_size > 0 ? cfg.frame_size : kDefaultFrameBuf;
    if (o.frame_size < kMinFrameBuf) {
        o.frame_size = kDefaultFrameBuf;
    }
    o.match_config    = cfg.traffic_match;
    configure(o);
}

bool AfPacketMirrorReader::open(const std::string& ifname, unsigned /*queue*/) {
    if (fd_ >= 0) {
        TCPLOG_WARN("AfPacketMirrorReader::open called on already-open socket (fd=%d)", fd_);
        return true;
    }

    if (frame_buf_.size() < kMinFrameBuf) {
        // Caller forgot to configure(); fall back to defaults so we don't
        // silently scribble on a zero-byte buffer.
        frame_buf_.assign(kDefaultFrameBuf, 0);
    }

    const int sock = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                              htons(ETH_P_ALL));
    if (sock < 0) {
        TCPLOG_ERROR("AF_PACKET socket() failed: %s", std::strerror(errno));
        return false;
    }

    const unsigned idx = resolve_ifindex(ifname);
    if (idx == 0) {
        TCPLOG_ERROR("AF_PACKET: unknown interface '%s': %s",
                     ifname.c_str(), std::strerror(errno));
        ::close(sock);
        return false;
    }

    sockaddr_ll addr{};
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = static_cast<int>(idx);
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        TCPLOG_ERROR("AF_PACKET bind('%s', idx=%u) failed: %s",
                     ifname.c_str(), idx, std::strerror(errno));
        ::close(sock);
        return false;
    }

    if (opts_.rcvbuf_bytes > 0) {
        const int rb = static_cast<int>(opts_.rcvbuf_bytes);
        if (::setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof(rb)) != 0 &&
            ::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb)) != 0) {
            TCPLOG_WARN("AF_PACKET SO_RCVBUF=%d on '%s' failed: %s",
                        rb, ifname.c_str(), std::strerror(errno));
        }
    }

    fd_      = sock;
    ifindex_ = idx;
    ifname_  = ifname;
    TCPLOG_INFO("AfPacketMirrorReader: tapping '%s' (ifindex=%u, fd=%d, frame=%zu)",
                ifname.c_str(), idx, fd_, frame_buf_.size());
    // AF_PACKET runs AFTER the XDP hook in the kernel: if a previous run
    // (or any other tool) left an XDP program attached on this interface,
    // it sees packets first and we only see whatever it returns XDP_PASS
    // for. With a stale "redirect" program from a prior active run, the
    // matched traffic gets redirected away from us and our [afpkt_counters]
    // line stays at rx=0. Surface this once at open so the operator has
    // somewhere to start when nothing arrives.
    TCPLOG_INFO("AfPacketMirrorReader: AF_PACKET runs after the XDP hook. "
                "If rx stays at 0, check for a leftover XDP program with "
                "`ip -d link show %s` and clean up via "
                "`sudo python3 scripts/xdp_attach.py --iface %s --mode drv --detach && "
                "sudo rm -rf /sys/fs/bpf/openpenny*`",
                ifname.c_str(), ifname.c_str());
    return true;
}

void AfPacketMirrorReader::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    ifindex_ = 0;
    ifname_.clear();
}

bool AfPacketMirrorReader::poll(const net::PacketHandler& handler, std::size_t budget) {
    if (fd_ < 0) return false;

    // Optional blocking wait. Non-blocking callers keep poll_timeout_ms=0
    // so they can busy-loop their own scheduler.
    if (opts_.poll_timeout_ms > 0) {
        pollfd pfd{fd_, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, opts_.poll_timeout_ms);
        if (rc <= 0) {
            // rc==0: timeout; rc<0 with EINTR: signal, just retry next poll.
            return true;
        }
    }

    const std::size_t cap = std::min(budget, opts_.batch);
    std::size_t drained = 0;

    while (drained < cap) {
        sockaddr_ll from{};
        socklen_t from_len = sizeof(from);

        const ssize_t n = ::recvfrom(fd_,
                                     frame_buf_.data(),
                                     frame_buf_.size(),
                                     0,
                                     reinterpret_cast<sockaddr*>(&from),
                                     &from_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                break;
            }
            TCPLOG_WARN("AF_PACKET recvfrom failed on '%s': %s",
                        ifname_.c_str(), std::strerror(errno));
            break;
        }
        if (n == 0) {
            break;
        }

        ++rx_packets_;

        if (opts_.drop_outgoing && from.sll_pkttype == PACKET_OUTGOING) {
            ++outgoing_skipped_;
            continue;
        }

        net::PacketView view{};
        if (!net::PacketParser::decode(frame_buf_.data(),
                                       static_cast<std::size_t>(n),
                                       view)) {
            ++decode_failures_;
            continue;
        }
        view.timestamp_ns = now_nanos();

        if (!opts_.match_config.empty() &&
            !net::traffic_matches_packet(opts_.match_config, view)) {
            ++filter_rejects_;
            continue;
        }

        ++handler_invocations_;
        if (handler) handler(view);
        ++drained;
    }

    // Periodic diagnostic, same 5s cadence as XDP's [xdp_counters]. Helps
    // pinpoint where packets disappear in the passive path:
    //   rx == 0          -> AF_PACKET socket isn't receiving anything
    //                       (interface down, RSS pre-filtering, or a
    //                        prior XDP program is intercepting all
    //                        traffic before AF_PACKET sees it).
    //   rx > 0, decode_fail close to rx -> non-IPv4 / truncated frames.
    //   rx > 0, filter_reject close to rx -> live traffic doesn't match
    //                                        the configured policy
    //                                        (rule-vs-traffic mismatch).
    //   handler == 0 with rx > 0 -> matches above two; nothing reaches
    //                               the pipeline.
    {
        const auto now = std::chrono::steady_clock::now();
        const bool first = last_counter_log_.time_since_epoch().count() == 0;
        if (first || now - last_counter_log_ >= std::chrono::seconds(5)) {
            last_counter_log_ = now;
            TCPLOG_INFO("[afpkt_counters] rx=%llu decode_fail=%llu "
                        "outgoing_skipped=%llu filter_rejected=%llu "
                        "handler_calls=%llu",
                        static_cast<unsigned long long>(rx_packets_),
                        static_cast<unsigned long long>(decode_failures_),
                        static_cast<unsigned long long>(outgoing_skipped_),
                        static_cast<unsigned long long>(filter_rejects_),
                        static_cast<unsigned long long>(handler_invocations_));
        }
    }
    return true;
}

bool AfPacketMirrorReader::update_match_rules(const net::TrafficMatchConfig& config) {
    opts_.match_config = config;
    return true;
}

} // namespace openpenny::ingress::af_packet
