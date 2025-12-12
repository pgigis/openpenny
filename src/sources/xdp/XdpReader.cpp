// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/sources/xdp/XdpReader.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"

#include <chrono>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <algorithm>

#ifdef OPENPENNY_WITH_LIBBPF
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>
#include <arpa/inet.h>
}
#endif

namespace openpenny {

namespace {

// High resolution monotonic timestamp used to annotate packet samples.
static uint64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

} // namespace

// Implementation detail that keeps the AF_XDP state.
struct XdpReader::Impl {
    Options opts{};
    bool configured{false};
    std::string ifname;
    unsigned queue{0};

#ifdef OPENPENNY_WITH_LIBBPF
    // AF_XDP resources and metadata that are only present when libbpf is available.
    struct RealState {
        bool ready{false};
        bool attached{false};
        bool pinned_maps{false};
        int ifindex{0};
        int conf_fd{-1};
        int xsks_fd{-1};
        int stats_fd{-1};
        int xdp_flags{0};
        bpf_object* obj{nullptr};
        xsk_umem* umem{nullptr};
        xsk_socket* xsk{nullptr};
        xsk_ring_prod fq{};
        xsk_ring_cons cq{};
        xsk_ring_cons rx{};
        xsk_ring_prod tx{};
        void* umem_area{nullptr};
        size_t umem_size{0};
        uint32_t frame_size{2048};
        uint32_t num_frames{4096};
        pollfd pfd{-1, POLLIN, 0};
        std::chrono::steady_clock::time_point last_queue_log{};
    } real;
#endif
};

void XdpReader::ImplDeleter::operator()(Impl* ptr) const {
    delete ptr;
}

// Ensure resources are torn down even if users forget to call close().
XdpReader::~XdpReader() {
    close();
}

/**
 * @brief Store explicit runtime options before opening the reader.
 */
void XdpReader::configure(const Options& opts) {
    if (!impl_) impl_.reset(new Impl());
    impl_->opts = opts;
    impl_->configured = true;
}

/**
 * @brief Translate persisted Config values into runtime-friendly Options.
 */
void XdpReader::configure_from_config(const Config& cfg) {
    // Translate the persisted Config structure into runtime Options
    // understood by the reader; this keeps the hot path free from YAML types.
    Options opts;
    opts.frame_size = cfg.frame_size;
    opts.num_frames = cfg.num_frames;
    opts.rx_ring = cfg.rx_ring;
    opts.prefer_drv_mode = cfg.xdp_drv_mode;
    opts.request_zerocopy = cfg.zerocopy;
    opts.enable_real_reader = cfg.xdp_runtime.enable;
    opts.attach_program = cfg.xdp_runtime.attach_program;
    opts.detach_on_close = cfg.xdp_runtime.detach_on_close;
    opts.reuse_pins = cfg.xdp_runtime.reuse_pins;
    opts.pin_maps = cfg.xdp_runtime.pin_maps;
    opts.update_conf_map = cfg.xdp_runtime.update_conf_map;
    opts.verbose = cfg.xdp_runtime.verbose;
    opts.drop_unmatched = cfg.xdp_runtime.drop_unmatched;
    opts.allow_ssh_bypass = cfg.xdp_runtime.allow_ssh_bypass;
    opts.allow_skb_fallback = cfg.xdp_runtime.allow_skb_fallback;
    opts.force_copy_mode = cfg.xdp_runtime.force_copy_mode;
    opts.require_zerocopy = cfg.xdp_runtime.require_zerocopy;
    opts.allow_copy_fallback = cfg.xdp_runtime.allow_copy_fallback;
    opts.batch = cfg.xdp_runtime.batch;
    opts.poll_timeout_ms = cfg.xdp_runtime.poll_timeout_ms;
    opts.bpf_object = cfg.xdp_runtime.bpf_object;
    opts.bpf_program = cfg.xdp_runtime.bpf_program;
    opts.map_conf_name = cfg.xdp_runtime.map_conf_name;
    opts.map_xsks_name = cfg.xdp_runtime.map_xsks_name;
    opts.map_stats_name = cfg.xdp_runtime.map_stats_name;
    opts.pin_conf_path = cfg.xdp_runtime.pin_conf_path;
    opts.pin_xsks_path = cfg.xdp_runtime.pin_xsks_path;
    opts.pin_stats_path = cfg.xdp_runtime.pin_stats_path;
    opts.prefix_host = cfg.xdp_runtime.prefix_host;
    opts.mask_host = cfg.xdp_runtime.mask_host;
    configure(opts);
}

bool XdpReader::open(const std::string& ifname, unsigned queue) {
    if (!impl_) impl_.reset(new Impl());
    auto& impl = *impl_;
    if (opened_) return true;

    if (!impl.configured) {
        configure(Options{});
    }

    impl.ifname = ifname;
    impl.queue = queue;

#ifndef OPENPENNY_WITH_LIBBPF
    TCPLOG_ERROR("libbpf support missing: install libbpf/libbpf-dev (or your distro equivalent) and rebuild openpenny.");
    return false;
#else
    if (!impl.opts.enable_real_reader) {
        TCPLOG_ERROR("AF_XDP reader disabled in configuration and no synthetic mode is available.");
        return false;
    }

    if (impl.opts.verbose) {
        TCPLOG_INFO("Attempting AF_XDP reader on %s queue %u", ifname.c_str(), queue);
    }

    auto bump_memlock = []() {
        rlimit r{RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
            TCPLOG_WARN("setrlimit MEMLOCK failed: %s", std::strerror(errno));
        }
    };

    bump_memlock();

    Impl::RealState& rs = impl.real;
    rs.frame_size = impl.opts.frame_size;
    rs.num_frames = impl.opts.num_frames;
    rs.umem_size = static_cast<size_t>(rs.frame_size) * rs.num_frames;

    rs.ifindex = if_nametoindex(ifname.c_str());
    if (rs.ifindex == 0) {
        TCPLOG_ERROR("if_nametoindex(%s) failed: %s", ifname.c_str(), std::strerror(errno));
        return false;
    }

    auto cleanup = [&]() {
        if (rs.xsk) { xsk_socket__delete(rs.xsk); rs.xsk = nullptr; }
        if (rs.umem) { xsk_umem__delete(rs.umem); rs.umem = nullptr; }
        if (rs.umem_area) { std::free(rs.umem_area); rs.umem_area = nullptr; }
        if (rs.conf_fd >= 0) { ::close(rs.conf_fd); rs.conf_fd = -1; }
        if (rs.xsks_fd >= 0) { ::close(rs.xsks_fd); rs.xsks_fd = -1; }
        if (rs.stats_fd >= 0) { ::close(rs.stats_fd); rs.stats_fd = -1; }
        if (rs.obj) { bpf_object__close(rs.obj); rs.obj = nullptr; }
        if (rs.attached && impl.opts.detach_on_close) {
            bpf_xdp_detach(rs.ifindex, rs.xdp_flags, nullptr);
        }
        rs.attached = false;
        rs.ready = false;
    };

    auto open_maps_from_object = [&](bpf_object* obj) -> bool {
        if (!obj) return false;
        bpf_map* conf = bpf_object__find_map_by_name(obj, impl.opts.map_conf_name.c_str());
        bpf_map* xsks = bpf_object__find_map_by_name(obj, impl.opts.map_xsks_name.c_str());
        bpf_map* stats = impl.opts.map_stats_name.empty() ? nullptr :
            bpf_object__find_map_by_name(obj, impl.opts.map_stats_name.c_str());
        if (!conf || !xsks) {
            TCPLOG_ERROR("Required maps (%s/%s) not found in %s",
                         impl.opts.map_conf_name.c_str(),
                         impl.opts.map_xsks_name.c_str(),
                         impl.opts.bpf_object.c_str());
            return false;
        }
        rs.conf_fd = bpf_map__fd(conf);
        rs.xsks_fd = bpf_map__fd(xsks);
        rs.stats_fd = stats ? bpf_map__fd(stats) : -1;
        return true;
    };

    auto open_maps_from_pins = [&]() -> bool {
        rs.conf_fd = bpf_obj_get(impl.opts.pin_conf_path.c_str());
        rs.xsks_fd = bpf_obj_get(impl.opts.pin_xsks_path.c_str());
        rs.stats_fd = impl.opts.pin_stats_path.empty() ? -1 : bpf_obj_get(impl.opts.pin_stats_path.c_str());
        if (rs.conf_fd < 0 || rs.xsks_fd < 0) {
            return false;
        }
        return true;
    };

    auto pin_maps = [&]() {
        if (rs.conf_fd >= 0) {
            bpf_obj_pin(rs.conf_fd, impl.opts.pin_conf_path.c_str());
        }
        if (rs.xsks_fd >= 0) {
            bpf_obj_pin(rs.xsks_fd, impl.opts.pin_xsks_path.c_str());
        }
        if (rs.stats_fd >= 0 && !impl.opts.pin_stats_path.empty()) {
            bpf_obj_pin(rs.stats_fd, impl.opts.pin_stats_path.c_str());
        }
    };

    auto attach_program = [&]() -> bool {
        int xdp_flags = impl.opts.prefer_drv_mode ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        rs.xdp_flags = xdp_flags;
        // Ensure clean slate before attaching our program.
        bpf_xdp_detach(rs.ifindex, XDP_FLAGS_DRV_MODE, nullptr);
        bpf_xdp_detach(rs.ifindex, XDP_FLAGS_SKB_MODE, nullptr);
        int rc = bpf_xdp_attach(rs.ifindex,
                                bpf_program__fd(bpf_object__find_program_by_name(rs.obj, impl.opts.bpf_program.c_str())),
                                xdp_flags,
                                nullptr);
        if (rc && impl.opts.allow_skb_fallback) {
            rs.xdp_flags = XDP_FLAGS_SKB_MODE;
            bpf_xdp_detach(rs.ifindex, rs.xdp_flags, nullptr);
            rc = bpf_xdp_attach(rs.ifindex,
                                bpf_program__fd(bpf_object__find_program_by_name(rs.obj, impl.opts.bpf_program.c_str())),
                                rs.xdp_flags,
                                nullptr);
        }
        if (rc) {
            TCPLOG_ERROR("bpf_xdp_attach failed on %s: %s", ifname.c_str(), std::strerror(-rc));
            return false;
        }
        rs.attached = true;
        return true;
    };

    auto update_conf_map = [&]() {
        struct {
            __u32 prefix;
            __u32 mask;
            __u32 qid;
        } conf_val{};
        conf_val.prefix = impl.opts.prefix_host;
        conf_val.mask = impl.opts.mask_host;
        conf_val.qid = queue;
        const __u32 key_queue = queue;
        const __u32 key0 = 0;
        bpf_map_info info{};
        __u32 info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(rs.conf_fd, &info, &info_len) == 0) {
            if (info.max_entries <= key_queue) {
                TCPLOG_ERROR(
                    "Conf map max_entries=%u; cannot program key=%u. Remove stale pins at %s and retry.",
                    info.max_entries,
                    key_queue,
                    impl.opts.pin_conf_path.c_str());
                return false;
            }
        }
        int rc = bpf_map_update_elem(rs.conf_fd, &key_queue, &conf_val, BPF_ANY);
        if (rc) {
            TCPLOG_ERROR("Failed to update conf map (queue %u): %s", queue, std::strerror(errno));
            return false;
        }
        // Also populate key 0 as a fallback/default.
        bpf_map_update_elem(rs.conf_fd, &key0, &conf_val, BPF_ANY);

        // Verify the programmed entry for this queue.
        struct {
            __u32 prefix;
            __u32 mask;
            __u32 qid;
        } check{};
        rc = bpf_map_lookup_elem(rs.conf_fd, &key_queue, &check);
        if (rc) {
            TCPLOG_ERROR("Failed to verify conf map for queue %u: %s", queue, std::strerror(errno));
            return false;
        }
        if (check.qid != queue) {
            TCPLOG_WARN("Conf map queue %u programmed qid=%u (expected %u)", queue, check.qid, queue);
        }
        return true;
    };

    auto setup_umem = [&]() -> bool {
        rs.umem_area = std::aligned_alloc(getpagesize(), rs.umem_size);
        if (!rs.umem_area) {
            TCPLOG_ERROR("Failed to allocate UMEM (%zu bytes)", rs.umem_size);
            return false;
        }

        xsk_umem_config umem_cfg{};
        umem_cfg.fill_size = rs.num_frames;
        umem_cfg.comp_size = rs.num_frames;
        umem_cfg.frame_size = rs.frame_size;
        umem_cfg.frame_headroom = 0;
        umem_cfg.flags = 0;

        int rc = xsk_umem__create(&rs.umem,
                                  rs.umem_area,
                                  rs.umem_size,
                                  &rs.fq,
                                  &rs.cq,
                                  &umem_cfg);
        if (rc) {
            TCPLOG_ERROR("xsk_umem__create failed: %s", std::strerror(-rc));
            return false;
        }
        return true;
    };

    auto setup_socket = [&]() -> bool {
        xsk_socket_config cfg{};
        cfg.rx_size = impl.opts.rx_ring;
        cfg.tx_size = 0;
        cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        cfg.xdp_flags = rs.xdp_flags;
        cfg.bind_flags = XDP_USE_NEED_WAKEUP;
        if (impl.opts.request_zerocopy || impl.opts.require_zerocopy) {
            cfg.bind_flags |= XDP_ZEROCOPY;
        } else if (impl.opts.force_copy_mode) {
            cfg.bind_flags |= XDP_COPY;
        }
        int rc = xsk_socket__create(&rs.xsk,
                                    ifname.c_str(),
                                    queue,
                                    rs.umem,
                                    &rs.rx,
                                    &rs.tx,
                                    &cfg);
        if (rc) {
            TCPLOG_ERROR("xsk_socket__create failed: %s", std::strerror(-rc));
            return false;
        }

        rs.pfd.fd = xsk_socket__fd(rs.xsk);
        rs.pfd.events = POLLIN;
        rs.ready = true;
        // Populate xsks_map with this socket for the configured queue (overwrite any stale entry).
        const __u32 xsk_fd = static_cast<__u32>(xsk_socket__fd(rs.xsk));
        const __u32 qkey = queue;
        if (bpf_map_update_elem(rs.xsks_fd, &qkey, &xsk_fd, BPF_ANY) != 0) {
            TCPLOG_ERROR("Failed to update xsks_map for queue %u: %s", queue, std::strerror(errno));
            return false;
        }
        // Verify xsks_map entry when supported.
        __u32 chk_fd = 0;
        int lrc = bpf_map_lookup_elem(rs.xsks_fd, &qkey, &chk_fd);
        if (lrc == 0 && chk_fd == 0) {
            TCPLOG_ERROR("xsks_map entry zero for queue %u", queue);
            return false;
        }
        if (lrc != 0 && errno != EOPNOTSUPP) {
            TCPLOG_ERROR("xsks_map lookup failed for queue %u: %s", queue, std::strerror(errno));
            return false;
        }
        return true;
    };

    auto remove_pins = [&]() {
        ::close(rs.conf_fd);
        ::close(rs.xsks_fd);
        ::close(rs.stats_fd);
        rs.conf_fd = rs.xsks_fd = rs.stats_fd = -1;
        (void)::unlink(impl.opts.pin_conf_path.c_str());
        (void)::unlink(impl.opts.pin_xsks_path.c_str());
        if (!impl.opts.pin_stats_path.empty()) {
            (void)::unlink(impl.opts.pin_stats_path.c_str());
        }
    };

    bool pins_ok = false;
    if (impl.opts.reuse_pins && open_maps_from_pins()) {
        bpf_map_info info{};
        __u32 info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(rs.conf_fd, &info, &info_len) == 0 &&
            impl.queue >= info.max_entries) {
            TCPLOG_ERROR(
                "Pinned conf map at %s supports only %u entries; need >= %u for queue %u. Removing stale pins.",
                impl.opts.pin_conf_path.c_str(),
                info.max_entries,
                impl.queue + 1,
                impl.queue);
            remove_pins();
        } else {
            pins_ok = true;
            rs.pinned_maps = true;
        }
    }

    if (!pins_ok) {
        rs.obj = bpf_object__open(impl.opts.bpf_object.c_str());
        if (!rs.obj) {
            TCPLOG_ERROR("Failed to open BPF object %s", impl.opts.bpf_object.c_str());
            cleanup();
            return false;
        }
        if (bpf_object__load(rs.obj)) {
            TCPLOG_ERROR("Failed to load BPF object %s", impl.opts.bpf_object.c_str());
            cleanup();
            return false;
        }
        if (!open_maps_from_object(rs.obj)) {
            cleanup();
            return false;
        }
        if (impl.opts.attach_program && !attach_program()) {
            cleanup();
            return false;
        }
        if (impl.opts.pin_maps) {
            pin_maps();
            rs.pinned_maps = true;
        }
    }

    if (impl.opts.update_conf_map && !update_conf_map()) {
        cleanup();
        return false;
    }

    if (!setup_umem()) {
        cleanup();
        return false;
    }

    if (!setup_socket()) {
        cleanup();
        return false;
    }

    // Pre-fill the fill queue with all frames.
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&rs.fq, rs.num_frames, &idx) == rs.num_frames) {
        for (uint32_t i = 0; i < rs.num_frames; ++i) {
            *xsk_ring_prod__fill_addr(&rs.fq, idx + i) = i * rs.frame_size;
        }
        xsk_ring_prod__submit(&rs.fq, rs.num_frames);
    }

    opened_ = true;
    return true;
#endif
}

void XdpReader::close() {
#ifdef OPENPENNY_WITH_LIBBPF
    if (!impl_) return;
    Impl::RealState& rs = impl_->real;
    // Clear xsks_map entry for this queue if possible to avoid stale FDs on restart.
    if (rs.xsks_fd >= 0) {
        __u32 key = impl_->queue;
        bpf_map_delete_elem(rs.xsks_fd, &key);
    }
    if (rs.xsk) { xsk_socket__delete(rs.xsk); rs.xsk = nullptr; }
    if (rs.umem) { xsk_umem__delete(rs.umem); rs.umem = nullptr; }
    if (rs.umem_area) { std::free(rs.umem_area); rs.umem_area = nullptr; }
    if (rs.attached && impl_->opts.detach_on_close) {
        bpf_xdp_detach(rs.ifindex, rs.xdp_flags, nullptr);
        rs.attached = false;
    }
#endif
    opened_ = false;
}

bool XdpReader::poll(const net::PacketHandler& handler, std::size_t budget) {
#ifndef OPENPENNY_WITH_LIBBPF
    (void)handler;
    (void)budget;
    TCPLOG_ERROR("libbpf support missing: install libbpf/libbpf-dev (or your distro equivalent) and rebuild openpenny.");
    return false;
#else
    auto& rs = impl_->real;
    if (!rs.ready || !rs.xsk) return false;

    const std::size_t max_batch = budget ? std::max<std::size_t>(budget, impl_->opts.batch)
                                         : impl_->opts.batch;
    std::size_t processed = 0;

    while (processed < max_batch) {
        uint32_t idx_rx = 0;
        uint32_t want = static_cast<uint32_t>(max_batch - processed);
        uint32_t rcvd = xsk_ring_cons__peek(&rs.rx, want, &idx_rx);
        if (!rcvd) {
            if (impl_->opts.poll_timeout_ms == 0) break;
            ::poll(&rs.pfd, 1, static_cast<int>(impl_->opts.poll_timeout_ms));
            rcvd = xsk_ring_cons__peek(&rs.rx, want, &idx_rx);
            if (!rcvd) break;
        }

        uint32_t refill_idx = 0;
        const uint32_t reserved = xsk_ring_prod__reserve(&rs.fq, rcvd, &refill_idx);
        const bool bulk_refill = reserved == rcvd;

        for (uint32_t i = 0; i < rcvd; ++i) {
            const xdp_desc* desc = xsk_ring_cons__rx_desc(&rs.rx, idx_rx + i);
            uint64_t addr = desc->addr;
            uint32_t len = desc->len;
            const uint8_t* pkt = static_cast<const uint8_t*>(rs.umem_area) + (addr & XSK_UNALIGNED_BUF_ADDR_MASK);

            net::PacketView packet{};
            if (net::PacketParser::decode(pkt, len, packet)) {
                packet.timestamp_ns = now_ns();
                handler(packet);
            }

            if (bulk_refill) {
                *xsk_ring_prod__fill_addr(&rs.fq, refill_idx + i) = addr;
            } else {
                uint32_t single_idx = 0;
                if (xsk_ring_prod__reserve(&rs.fq, 1, &single_idx) == 1) {
                    *xsk_ring_prod__fill_addr(&rs.fq, single_idx) = addr;
                    xsk_ring_prod__submit(&rs.fq, 1);
                }
            }
        }

        if (bulk_refill) {
            xsk_ring_prod__submit(&rs.fq, rcvd);
        }

        xsk_ring_cons__release(&rs.rx, rcvd);
        processed += rcvd;

        if (!budget) break;

        if (TCPLOG_ENABLED(INFO)) {
            auto now = std::chrono::steady_clock::now();
            if (rs.last_queue_log.time_since_epoch().count() == 0) {
                rs.last_queue_log = now;
            }
            if (now - rs.last_queue_log >= std::chrono::seconds(5)) {
                const uint32_t fq_free = xsk_prod_nb_free(&rs.fq, rs.num_frames);
                rs.last_queue_log = now;
                TCPLOG_INFO("[xdp_queue] rx_batch=%u rx_ring=%u fq_free=%u fq_cap=%u",
                            rcvd,
                            impl_->opts.rx_ring,
                            fq_free,
                            rs.num_frames);
            }
        }
    }

    return true;
#endif
}

} // namespace openpenny
