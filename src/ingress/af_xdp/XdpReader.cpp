// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/ingress/af_xdp/XdpReader.h"

#include "XdpRuleController.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <vector>

#ifdef OPENPENNY_WITH_LIBBPF
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

struct SharedAttachState {
    std::mutex mutex;
    unsigned refs{0};
    bool rss_checked{false};   ///< Only the first-opening worker runs the RSS coverage check.
#ifdef OPENPENNY_WITH_LIBBPF
    bool attached{false};
    int ifindex{0};
    int xdp_flags{0};
#endif
};

std::mutex g_shared_attach_states_mutex;
std::map<std::string, std::shared_ptr<SharedAttachState>> g_shared_attach_states;

// The shared-attach key is derived from the pin paths because that is how
// sibling queue workers recognise that they are targeting the same attached
// XDP program / pinned maps. Since the pin paths moved from the public
// Options into the impl-private Tuning struct, this helper now takes the
// paths directly rather than a reference to a struct external callers
// shouldn't need to name.
std::string shared_attach_key(const std::string& ifname,
                              const std::string& pin_conf_path,
                              const std::string& pin_xsks_path,
                              const std::string& pin_settings_path) {
    return ifname + "|" +
           pin_conf_path + "|" +
           pin_xsks_path + "|" +
           pin_settings_path;
}

std::shared_ptr<SharedAttachState> get_shared_attach_state(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_shared_attach_states_mutex);
    auto& state = g_shared_attach_states[key];
    if (!state) {
        state = std::make_shared<SharedAttachState>();
    }
    return state;
}

void release_shared_attach_state(const std::string& key,
                                 const std::shared_ptr<SharedAttachState>& state) {
    std::lock_guard<std::mutex> lock(g_shared_attach_states_mutex);
    auto it = g_shared_attach_states.find(key);
    if (it != g_shared_attach_states.end() && it->second == state && state->refs == 0) {
        g_shared_attach_states.erase(it);
    }
}

bool ensure_pin_parent_dir(const std::string& pin_path) {
    if (pin_path.empty()) return true;
    std::error_code ec;
    const auto parent = std::filesystem::path(pin_path).parent_path();
    if (parent.empty()) return true;
    if (std::filesystem::exists(parent, ec)) return true;
    if (std::filesystem::create_directories(parent, ec)) return true;
    if (!ec && std::filesystem::exists(parent)) return true;
    TCPLOG_ERROR("Failed to create bpffs directory %s: %s",
                 parent.string().c_str(),
                 ec ? ec.message().c_str() : "unknown error");
    return false;
}

#ifdef OPENPENNY_WITH_LIBBPF
// Read the NIC's RSS indirection table via the ethtool ioctl (ETHTOOL_GRSSH).
//
// Returns the table as a vector of queue ids (one entry per RSS bucket), or
// std::nullopt if the driver doesn't support indirection reads (some virtual
// NICs, loopback, some cloud vNICs). The table's size is driver-dependent
// (typical: 128 on Intel, 256–512 on Mellanox).
//
// We deliberately use the ioctl (not netlink) because it's universally
// supported on any kernel that has AF_XDP, and we already have the headers.
std::optional<std::vector<std::uint32_t>> read_rss_indir_table(const std::string& ifname) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::nullopt;

    // Phase 1: ask the driver for the table size (indir_size=0, key_size=0).
    ethtool_rxfh head{};
    head.cmd = ETHTOOL_GRSSH;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_data = reinterpret_cast<char*>(&head);

    if (::ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        ::close(fd);
        return std::nullopt;
    }
    const std::uint32_t n_indir = head.indir_size;
    const std::uint32_t n_key   = head.key_size;
    if (n_indir == 0) {
        ::close(fd);
        return std::nullopt;
    }

    // Phase 2: allocate a buffer large enough to hold the header + the
    // indirection table + the hash key, then re-issue with indir_size/key_size
    // populated so the kernel fills in the trailing data.
    const std::size_t total_bytes = sizeof(ethtool_rxfh) + (n_indir + n_key) * sizeof(std::uint32_t);
    std::vector<std::uint8_t> buf(total_bytes, 0);
    auto* req = reinterpret_cast<ethtool_rxfh*>(buf.data());
    req->cmd        = ETHTOOL_GRSSH;
    req->indir_size = n_indir;
    req->key_size   = n_key;
    ifr.ifr_data    = reinterpret_cast<char*>(req);

    if (::ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
        ::close(fd);
        return std::nullopt;
    }

    // The indirection table is laid out immediately after the ethtool_rxfh header.
    std::vector<std::uint32_t> indir(n_indir);
    const auto* table = reinterpret_cast<const std::uint32_t*>(buf.data() + sizeof(ethtool_rxfh));
    for (std::uint32_t i = 0; i < n_indir; ++i) {
        indir[i] = table[i];
    }
    ::close(fd);
    return indir;
}
#endif

#ifdef OPENPENNY_WITH_LIBBPF
bool pin_map_fd(int fd, const std::string& path) {
    if (fd < 0 || path.empty()) return true;
    if (!ensure_pin_parent_dir(path)) return false;
    if (bpf_obj_pin(fd, path.c_str()) == 0) return true;
    if (errno == EEXIST) {
        if (::unlink(path.c_str()) != 0) {
            TCPLOG_ERROR("Failed to replace pinned map at %s: %s",
                         path.c_str(),
                         std::strerror(errno));
            return false;
        }
        if (bpf_obj_pin(fd, path.c_str()) == 0) return true;
    }
    TCPLOG_ERROR("Failed to pin BPF map at %s: %s", path.c_str(), std::strerror(errno));
    return false;
}
#endif

} // namespace

// Implementation detail that keeps the AF_XDP state.
struct XdpReader::Impl {
    Options opts{};

    /**
     * @brief Impl-private low-level tuning populated from Config::xdp_runtime.
     *
     * These fields used to live on XdpReader::Options which forced every TU
     * that included XdpReader.h to understand BPF / pin / attach semantics.
     * They are now set only inside configure_from_config(Config) and read by
     * open() / close() / update_match_rules() here in the .cpp; external
     * callers don't see them.
     */
    struct Tuning {
        // XDP attach lifecycle
        bool attach_program      = true;
        bool detach_on_close     = true;
        bool reuse_pins          = false;
        bool pin_maps            = true;
        bool update_conf_map     = true;
        bool verbose             = false;
        bool drop_unmatched      = false;
        bool allow_ssh_bypass    = true;
        bool allow_skb_fallback  = false;

        // AF_XDP bind-flag policy
        bool force_copy_mode     = false;
        bool require_zerocopy    = true;
        bool allow_copy_fallback = false;
        bool prefer_drv_mode     = true;
        bool request_zerocopy    = true;

        // BPF object / program / map names
        std::string bpf_object       = "xdp_redirect_openpenny.o";
        std::string bpf_program      = "xdp_redirect_openpenny";
        std::string map_conf_name    = "conf";
        std::string map_xsks_name    = "xsks_map";
        std::string map_stats_name   = "counters";
        std::string map_settings_name = "settings";

        // bpffs pin paths
        std::string pin_conf_path     = "/sys/fs/bpf/openpenny_conf";
        std::string pin_xsks_path     = "/sys/fs/bpf/openpenny_xsks";
        std::string pin_stats_path    = "/sys/fs/bpf/openpenny_stats";
        std::string pin_settings_path = "/sys/fs/bpf/openpenny_settings";

        // Deprecated prefix metadata retained for backwards-compat request
        // plumbing; normally overridden by match_config.
        uint32_t prefix_host = 0;
        uint32_t mask_host   = 0;
    } tuning{};

    bool configured{false};
    std::string ifname;
    unsigned queue{0};
    std::string shared_attach_key;
    std::shared_ptr<SharedAttachState> shared_attach;

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
        int settings_fd{-1};
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
        std::chrono::steady_clock::time_point last_counter_log{};
        std::chrono::steady_clock::time_point last_xdp_stats_sample{};
        // Last sampled values from getsockopt(XDP_STATISTICS); we accumulate
        // deltas into the process-wide atomics.
        std::uint64_t last_rx_dropped{0};
        std::uint64_t last_rx_invalid{0};
        std::uint64_t last_rx_ring_full{0};
        std::uint64_t last_rx_fq_empty{0};
        std::uint64_t rx_packets{0};
        std::uint64_t decode_failures{0};
    } real;
#endif
};

#ifdef OPENPENNY_WITH_LIBBPF
namespace {

// Process-wide AF_XDP userspace counters (sum across every queue worker).
// These are the userspace mirror of the kernel "[xdp_counters]" line: they
// answer "did the packet that the kernel handed to AF_XDP actually surface
// in xsk_ring_cons__peek and survive PacketParser::decode?". When kernel
// xsk_hit is large but userspace_rx is 0 we know the RX ring is never being
// drained; when userspace_rx == decode_fail we know decode is rejecting
// every frame.
std::atomic<std::uint64_t> g_userspace_rx_packets{0};
std::atomic<std::uint64_t> g_userspace_decode_failures{0};
std::atomic<std::uint64_t> g_userspace_peek_zero{0};
std::atomic<std::uint64_t> g_userspace_poll_calls{0};

// Per-socket kernel statistics aggregated across every queue worker. These
// are what the kernel reports via getsockopt(SOL_XDP, XDP_STATISTICS):
//   rx_dropped              -> packet redirected to the socket but dropped
//                              after that (e.g. socket-level drop).
//   rx_invalid_descs        -> malformed RX descriptor.
//   rx_ring_full            -> kernel tried to enqueue but the RX ring was
//                              already full (consumer too slow).
//   rx_fill_ring_empty      -> fill ring had no frames available.
// If kernel xsk_hit is high but ALL of these are 0 alongside userspace_rx=0,
// the kernel never even reached the socket — the redirect itself is failing
// (typical cause: socket bound to a different queue than the xsks_map key,
// or the AF_XDP socket isn't visible to the attached XDP program because
// the program references a different xsks_map instance).
std::atomic<std::uint64_t> g_xdp_stats_rx_dropped{0};
std::atomic<std::uint64_t> g_xdp_stats_rx_invalid{0};
std::atomic<std::uint64_t> g_xdp_stats_rx_ring_full{0};
std::atomic<std::uint64_t> g_xdp_stats_rx_fq_empty{0};

// Bind-mode counters. Each worker bumps exactly one of these after a
// successful xsk_socket__create() so we can detect the silent multi-queue
// failure mode where zerocopy was REQUESTED but the kernel only granted
// it on a subset of queues. A heterogeneous set
// (zerocopy>0 AND copy>0) at startup is a strong indicator the redirect
// path will misbehave on the queues that fell back, because the attached
// XDP program is still in DRV (zerocopy) mode.
std::atomic<std::uint32_t> g_bind_mode_zerocopy{0};
std::atomic<std::uint32_t> g_bind_mode_copy{0};

// With XDP_USE_NEED_WAKEUP the kernel may require an explicit syscall before
// it resumes RX processing for this AF_XDP socket.
bool wake_rx_if_needed(xsk_socket* xsk, xsk_ring_prod& fq) {
    if (!xsk) return true;
    if (!xsk_ring_prod__needs_wakeup(&fq)) return true;
    if (::recvfrom(xsk_socket__fd(xsk), nullptr, 0, MSG_DONTWAIT, nullptr, nullptr) >= 0) {
        return true;
    }
    if (errno == EAGAIN || errno == EBUSY || errno == EINTR) {
        return true;
    }
    TCPLOG_WARN("AF_XDP RX wakeup failed: %s", std::strerror(errno));
    return false;
}

} // namespace
#endif

void XdpReader::ImplDeleter::operator()(Impl* ptr) const {
    delete ptr;
}

// Ensure resources are torn down even if users forget to call close().
XdpReader::~XdpReader() {
    close();
}

/**
 * @brief Store explicit runtime options before opening the reader.
 *
 * Kept public so SDK-style callers can still drive the reader directly, but
 * note that the BPF-attachment tuning (pin paths, attach policy, etc.) is
 * now set only inside configure_from_config(): passing an Options here
 * leaves the impl-private Tuning at its defaults, which is the right
 * behaviour for every caller that's already going through Config.
 */
void XdpReader::configure(const Options& opts) {
    if (!impl_) impl_.reset(new Impl());
    impl_->opts = opts;
    impl_->configured = true;
}

/**
 * @brief Translate persisted Config values into runtime-friendly Options
 *        and the impl-private Tuning struct.
 *
 * This is the single entry point that external callers (CLI, worker,
 * gRPC service) actually use, and it owns the mapping from YAML-shaped
 * Config::xdp_runtime into the low-level BPF tuning that used to live on
 * the public Options struct.
 */
void XdpReader::configure_from_config(const Config& cfg) {
    if (!impl_) impl_.reset(new Impl());

    // Public Options — the subset the surrounding pipeline actually observes.
    Options opts;
    opts.enable_real_reader = cfg.xdp_runtime.enable;
    opts.batch = cfg.xdp_runtime.batch;
    opts.poll_timeout_ms = cfg.xdp_runtime.poll_timeout_ms;
    opts.frame_size = cfg.frame_size;
    opts.num_frames = cfg.num_frames;
    opts.rx_ring = cfg.rx_ring;
    opts.match_config = cfg.traffic_match;
    // Note: cfg.queue gets rewritten per-worker by OpenpennyPipelineDriver's
    // run_queue_worker (it does `cfg_local.queue = base + idx`). cfg.queue_base
    // is invariant — it reflects the base queue parsed from YAML and is never
    // rewritten, so it's the right value to use for the RSS served-set check.
    opts.base_queue = cfg.queue_base;
    opts.queue_count = std::max(1u, cfg.queue_count);
    impl_->opts = opts;

    // Impl-private Tuning — all the BPF attach / pin / map plumbing that
    // used to leak through XdpReader::Options into every includer.
    Impl::Tuning& t = impl_->tuning;
    t.prefer_drv_mode     = cfg.xdp_drv_mode;
    t.request_zerocopy    = cfg.zerocopy;
    t.attach_program      = cfg.xdp_runtime.attach_program;
    t.detach_on_close     = cfg.xdp_runtime.detach_on_close;
    t.reuse_pins          = cfg.xdp_runtime.reuse_pins;
    t.pin_maps            = cfg.xdp_runtime.pin_maps;
    t.update_conf_map     = cfg.xdp_runtime.update_conf_map;
    t.verbose             = cfg.xdp_runtime.verbose;
    t.drop_unmatched      = cfg.xdp_runtime.drop_unmatched;
    t.allow_ssh_bypass    = cfg.xdp_runtime.allow_ssh_bypass;
    t.allow_skb_fallback  = cfg.xdp_runtime.allow_skb_fallback;
    t.force_copy_mode     = cfg.xdp_runtime.force_copy_mode;
    t.require_zerocopy    = cfg.xdp_runtime.require_zerocopy;
    t.allow_copy_fallback = cfg.xdp_runtime.allow_copy_fallback;
    t.bpf_object          = cfg.xdp_runtime.bpf_object;
    t.bpf_program         = cfg.xdp_runtime.bpf_program;
    t.map_conf_name       = cfg.xdp_runtime.map_conf_name;
    t.map_xsks_name       = cfg.xdp_runtime.map_xsks_name;
    t.map_stats_name      = cfg.xdp_runtime.map_stats_name;
    t.map_settings_name   = cfg.xdp_runtime.map_settings_name;
    t.pin_conf_path       = cfg.xdp_runtime.pin_conf_path;
    t.pin_xsks_path       = cfg.xdp_runtime.pin_xsks_path;
    t.pin_stats_path      = cfg.xdp_runtime.pin_stats_path;
    t.pin_settings_path   = cfg.xdp_runtime.pin_settings_path;
    t.prefix_host         = cfg.xdp_runtime.prefix_host;
    t.mask_host           = cfg.xdp_runtime.mask_host;

    if (cfg.queue_count > 1) {
        // Multi-queue AF_XDP shares one attached XDP program and one set of maps
        // across queue-bound sockets, so pinned maps become an internal requirement.
        t.pin_maps = true;
        t.reuse_pins = true;
    }

    impl_->configured = true;
}

bool XdpReader::update_match_rules(const net::TrafficMatchConfig& config) {
    if (!impl_) impl_.reset(new Impl());
    impl_->opts.match_config = config;

#ifndef OPENPENNY_WITH_LIBBPF
    return !opened_;
#else
    if (!opened_) return true;
    auto& rs = impl_->real;
    return xdp::program_xdp_match_rules(
        xdp::XdpRuleMapFds{rs.conf_fd, rs.settings_fd},
        impl_->opts.match_config,
        impl_->queue,
        impl_->tuning.drop_unmatched,
        impl_->tuning.allow_ssh_bypass);
#endif
}

// ---------------------------------------------------------------------------
// XdpReader::open()
//
// Open the AF_XDP data path on (ifname, queue). Internally this performs
// the full lifecycle required by a zerocopy-capable native-XDP pipeline:
//
//   1. Locate / load the BPF object and its maps (reusing bpffs pins when
//      configured and compatible).
//   2. Publish pass-only defaults into the settings map so that attaching
//      the XDP program cannot disrupt live traffic while we finish setup.
//   3. Attach the XDP program (unless we are re-using an existing attach).
//   4. Allocate UMEM, create the AF_XDP socket on (ifname, queue), pre-fill
//      the fill ring with every frame so the driver can start RX.
//   5. Publish the AF_XDP socket fd into xsks_map[queue] so the XDP
//      program's bpf_redirect_map() can reach us.
//   6. Publish the real traffic-match rules into the conf/settings maps.
//
// The order matters: rules that can redirect are programmed AFTER xsks_map
// is populated so we never hit a window where the XDP program returns
// XDP_REDIRECT for a queue that has no live AF_XDP socket attached.
// ---------------------------------------------------------------------------
bool XdpReader::open(const std::string& ifname, unsigned queue) {
    if (!impl_) impl_.reset(new Impl());
    auto& impl = *impl_;
    if (opened_) return true;

    if (!impl.configured) {
        configure(Options{});
    }

    impl.ifname = ifname;
    impl.queue = queue;
    impl.shared_attach_key = shared_attach_key(ifname,
                                                impl.tuning.pin_conf_path,
                                                impl.tuning.pin_xsks_path,
                                                impl.tuning.pin_settings_path);
    impl.shared_attach = get_shared_attach_state(impl.shared_attach_key);

#ifndef OPENPENNY_WITH_LIBBPF
    TCPLOG_ERROR("libbpf support missing: install libbpf/libbpf-dev "
                 "(or your distro equivalent) and rebuild openpenny.");
    return false;
#else
    if (!impl.opts.enable_real_reader) {
        TCPLOG_ERROR("AF_XDP reader disabled in configuration and no synthetic mode is available.");
        return false;
    }

    // Serialise the per-interface attach / map-pin dance across worker
    // threads so two queue workers on the same NIC can't race when creating
    // or pinning the shared BPF objects.
    std::lock_guard<std::mutex> shared_lock(impl.shared_attach->mutex);

    if (impl.tuning.verbose) {
        TCPLOG_INFO("Attempting AF_XDP reader on %s queue %u", ifname.c_str(), queue);
    }

    // --- Step 1: environment prep ------------------------------------------

    // UMEM allocation and XDP attach both draw on RLIMIT_MEMLOCK on older
    // kernels (pre-5.11). Raising the limit is cheap when we already have
    // CAP_SYS_RESOURCE and harmless otherwise.
    rlimit r{RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        TCPLOG_WARN("setrlimit MEMLOCK failed: %s", std::strerror(errno));
    }

    Impl::RealState& rs = impl.real;
    rs.frame_size = impl.opts.frame_size;
    rs.num_frames = impl.opts.num_frames;
    rs.umem_size  = static_cast<size_t>(rs.frame_size) * rs.num_frames;

    rs.ifindex = if_nametoindex(ifname.c_str());
    if (rs.ifindex == 0) {
        TCPLOG_ERROR("if_nametoindex(%s) failed: %s", ifname.c_str(), std::strerror(errno));
        return false;
    }

    // Teardown helper for early-exit paths below. Anything created during
    // open() needs to be released before we return false.
    auto cleanup = [&]() {
        if (rs.xsk)       { xsk_socket__delete(rs.xsk);  rs.xsk = nullptr; }
        if (rs.umem)      { xsk_umem__delete(rs.umem);   rs.umem = nullptr; }
        if (rs.umem_area) { std::free(rs.umem_area);     rs.umem_area = nullptr; }
        if (rs.conf_fd >= 0)     { ::close(rs.conf_fd);     rs.conf_fd = -1; }
        if (rs.xsks_fd >= 0)     { ::close(rs.xsks_fd);     rs.xsks_fd = -1; }
        if (rs.stats_fd >= 0)    { ::close(rs.stats_fd);    rs.stats_fd = -1; }
        if (rs.settings_fd >= 0) { ::close(rs.settings_fd); rs.settings_fd = -1; }
        if (rs.obj)       { bpf_object__close(rs.obj);   rs.obj = nullptr; }
        if (rs.attached && impl.tuning.detach_on_close) {
            bpf_xdp_detach(rs.ifindex, rs.xdp_flags, nullptr);
        }
        rs.attached = false;
        rs.ready    = false;
    };

    // Populate rs.*_fd from a freshly loaded bpf_object.
    auto open_maps_from_object = [&](bpf_object* obj) -> bool {
        if (!obj) return false;
        bpf_map* conf = bpf_object__find_map_by_name(obj, impl.tuning.map_conf_name.c_str());
        // Backwards compat: older configs used "conf" unconditionally.
        if (!conf && impl.tuning.map_conf_name != "conf") {
            conf = bpf_object__find_map_by_name(obj, "conf");
        }
        bpf_map* xsks = bpf_object__find_map_by_name(obj, impl.tuning.map_xsks_name.c_str());
        bpf_map* stats = impl.tuning.map_stats_name.empty() ? nullptr :
            bpf_object__find_map_by_name(obj, impl.tuning.map_stats_name.c_str());
        bpf_map* settings = impl.tuning.map_settings_name.empty() ? nullptr :
            bpf_object__find_map_by_name(obj, impl.tuning.map_settings_name.c_str());
        if (!conf || !xsks || !settings) {
            TCPLOG_ERROR("Required maps (%s / %s / %s) not found in %s",
                         impl.tuning.map_conf_name.c_str(),
                         impl.tuning.map_xsks_name.c_str(),
                         impl.tuning.map_settings_name.c_str(),
                         impl.tuning.bpf_object.c_str());
            return false;
        }
        rs.conf_fd     = bpf_map__fd(conf);
        rs.xsks_fd     = bpf_map__fd(xsks);
        rs.stats_fd    = stats ? bpf_map__fd(stats) : -1;
        rs.settings_fd = bpf_map__fd(settings);
        return true;
    };

    // Populate rs.*_fd by opening the pre-pinned maps under /sys/fs/bpf.
    // Returns false if any required pin is missing.
    auto open_maps_from_pins = [&]() -> bool {
        rs.conf_fd     = bpf_obj_get(impl.tuning.pin_conf_path.c_str());
        rs.xsks_fd     = bpf_obj_get(impl.tuning.pin_xsks_path.c_str());
        rs.stats_fd    = impl.tuning.pin_stats_path.empty()    ? -1 : bpf_obj_get(impl.tuning.pin_stats_path.c_str());
        rs.settings_fd = impl.tuning.pin_settings_path.empty() ? -1 : bpf_obj_get(impl.tuning.pin_settings_path.c_str());
        if (rs.conf_fd < 0 || rs.xsks_fd < 0 || rs.settings_fd < 0) {
            if (rs.conf_fd >= 0)     { ::close(rs.conf_fd);     rs.conf_fd = -1; }
            if (rs.xsks_fd >= 0)     { ::close(rs.xsks_fd);     rs.xsks_fd = -1; }
            if (rs.stats_fd >= 0)    { ::close(rs.stats_fd);    rs.stats_fd = -1; }
            if (rs.settings_fd >= 0) { ::close(rs.settings_fd); rs.settings_fd = -1; }
            return false;
        }
        return true;
    };

    // Persist the loaded maps under /sys/fs/bpf so sibling workers can find
    // them and so they survive across restarts for inspection.
    auto pin_maps = [&]() {
        return pin_map_fd(rs.conf_fd,     impl.tuning.pin_conf_path) &&
               pin_map_fd(rs.xsks_fd,     impl.tuning.pin_xsks_path) &&
               pin_map_fd(rs.stats_fd,    impl.tuning.pin_stats_path) &&
               pin_map_fd(rs.settings_fd, impl.tuning.pin_settings_path);
    };

    // Attach the loaded XDP program to the interface.
    //
    // We first blow away any previously attached program in either mode to
    // avoid the "other XDP program already attached" EBUSY that otherwise
    // surfaces on repeat runs. We then attempt DRV (native) or SKB mode
    // per config, with optional SKB fallback if DRV fails (common on
    // virtual interfaces that have no native XDP support).
    auto attach_program = [&]() -> bool {
        int xdp_flags = impl.tuning.prefer_drv_mode ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        rs.xdp_flags = xdp_flags;

        bpf_xdp_detach(rs.ifindex, XDP_FLAGS_DRV_MODE, nullptr);
        bpf_xdp_detach(rs.ifindex, XDP_FLAGS_SKB_MODE, nullptr);

        int prog_fd = bpf_program__fd(
            bpf_object__find_program_by_name(rs.obj, impl.tuning.bpf_program.c_str()));
        int rc = bpf_xdp_attach(rs.ifindex, prog_fd, xdp_flags, nullptr);

        if (rc && impl.tuning.allow_skb_fallback) {
            TCPLOG_WARN("bpf_xdp_attach on %s in DRV mode failed (%s); "
                        "falling back to SKB generic mode",
                        ifname.c_str(), std::strerror(-rc));
            rs.xdp_flags = XDP_FLAGS_SKB_MODE;
            bpf_xdp_detach(rs.ifindex, rs.xdp_flags, nullptr);
            rc = bpf_xdp_attach(rs.ifindex, prog_fd, rs.xdp_flags, nullptr);
        }
        if (rc) {
            TCPLOG_ERROR("bpf_xdp_attach failed on %s: %s",
                         ifname.c_str(), std::strerror(-rc));
            return false;
        }
        rs.attached = true;
        return true;
    };

    // Push the *real* match rules into conf/settings. Safe to call only
    // after xsks_map[queue] already holds our socket fd (otherwise matches
    // would redirect to a queue with no listener).
    auto update_match_maps = [&]() {
        return xdp::program_xdp_match_rules(
            xdp::XdpRuleMapFds{rs.conf_fd, rs.settings_fd},
            impl.opts.match_config,
            queue,
            impl.tuning.drop_unmatched,
            impl.tuning.allow_ssh_bypass);
    };

    // Allocate the UMEM region (a page-aligned slab of memory divided into
    // fixed-size frames) and hand it to libxdp so it can set up the fill and
    // completion rings. Each RX descriptor the kernel produces references an
    // address inside this region; userspace reads the packet from that offset.
    auto setup_umem = [&]() -> bool {
        rs.umem_area = std::aligned_alloc(getpagesize(), rs.umem_size);
        if (!rs.umem_area) {
            TCPLOG_ERROR("Failed to allocate UMEM (%zu bytes)", rs.umem_size);
            return false;
        }
        std::memset(rs.umem_area, 0, rs.umem_size);

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

    // Create the AF_XDP socket and bind it to (ifname, queue). We intentionally
    // prevent libxdp from loading its own default XDP program (INHIBIT_PROG_LOAD)
    // because OpenPenny owns the attached program.
    auto setup_socket = [&]() -> bool {
        xsk_socket_config cfg{};
        cfg.rx_size      = impl.opts.rx_ring;
        cfg.tx_size      = impl.opts.rx_ring;
        cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

        // cfg.xdp_flags must reflect the mode of the *already-attached* XDP
        // program (DRV vs SKB). libxdp reads it to decide how to bind the
        // socket's RX/TX rings to the driver. Passing 0 makes libxdp
        // misinterpret the mode on some kernels and silently breaks RX.
        cfg.xdp_flags = rs.xdp_flags;

        // Start with XDP_USE_NEED_WAKEUP, which is the modern contract between
        // kernel zerocopy drivers and userspace: the kernel sets a "please poke
        // me" bit in the fill ring, userspace calls recvfrom() to wake the
        // driver. Without it, xsk_ring_prod__needs_wakeup() always returns 0
        // and the whole wake_rx_if_needed() path becomes a no-op — on most
        // native-XDP NICs (mlx5, i40e, ice) that means the driver never
        // refills RX and no packets ever appear in userspace.
        cfg.bind_flags = XDP_USE_NEED_WAKEUP;

        if (impl.tuning.request_zerocopy || impl.tuning.require_zerocopy) {
            cfg.bind_flags |= XDP_ZEROCOPY;
        } else if (impl.tuning.force_copy_mode) {
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
            TCPLOG_ERROR("xsk_socket__create failed on %s queue %u: %s",
                         ifname.c_str(), queue, std::strerror(-rc));
            return false;
        }

        rs.pfd.fd    = xsk_socket__fd(rs.xsk);
        rs.pfd.events = POLLIN;
        rs.ready     = true;

        // Authoritative check: ask the kernel which (ifindex, queue_id)
        // the socket actually bound to via getsockname(). The kernel's
        // xsk_getname() returns the bound sockaddr_xdp.
        //
        // Why this matters for the multi-queue zero-packet bug:
        // bpf_redirect_map(&xsks_map, qid, ...) at runtime checks
        //   xs->dev == ctx->ingress_ifindex   AND
        //   xs->queue_id == ctx->rx_queue_index
        // If either check fails the redirect is silently dropped. The
        // BPF-side xsk_hit counter is incremented BEFORE the kernel
        // does that check, so xsk_hit > 0 with userspace_rx == 0 is
        // exactly what a queue/ifindex mismatch looks like. This log
        // line lets us prove or rule that out for every worker.
        sockaddr_xdp bound_addr{};
        socklen_t bound_len = sizeof(bound_addr);
        if (::getsockname(rs.pfd.fd,
                          reinterpret_cast<sockaddr*>(&bound_addr),
                          &bound_len) == 0) {
            const std::uint32_t bound_queue = bound_addr.sxdp_queue_id;
            const std::uint32_t bound_ifindex = bound_addr.sxdp_ifindex;
            TCPLOG_DEBUG(
                "[xdp_bind] queue=%u: kernel reports bound to "
                "ifindex=%u queue_id=%u (we asked for queue=%u "
                "ifindex=%d)",
                queue,
                bound_ifindex, bound_queue,
                queue, rs.ifindex);
            if (bound_queue != queue) {
                TCPLOG_ERROR(
                    "[xdp_bind] queue=%u: SOCKET BOUND TO WRONG QUEUE! "
                    "Asked for queue %u but kernel bound to queue %u. "
                    "This is the most likely cause of the multi-queue "
                    "zero-packet bug: bpf_redirect_map(xsks_map, %u, ...) "
                    "will silently drop packets because the socket at "
                    "xsks_map[%u] is bound to queue %u != %u. Refusing "
                    "to continue.",
                    queue, queue, bound_queue,
                    queue, queue, bound_queue, queue);
                return false;
            }
            if (rs.ifindex != 0 &&
                bound_ifindex != static_cast<std::uint32_t>(rs.ifindex)) {
                TCPLOG_ERROR(
                    "[xdp_bind] queue=%u: socket bound to ifindex %u "
                    "but the XDP program is attached to ifindex %d. "
                    "Redirects will silently fail at the kernel "
                    "boundary. Refusing to continue.",
                    queue, bound_ifindex, rs.ifindex);
                return false;
            }
        } else {
            TCPLOG_DEBUG(
                "[xdp_bind] queue=%u: getsockname() failed: %s "
                "(can't verify bound queue id)",
                queue, std::strerror(errno));
        }

        // Verify the bind mode the kernel actually granted. We REQUEST
        // XDP_ZEROCOPY when configured to, but the kernel may silently
        // fall back to copy mode for some queues even after a successful
        // bind. A heterogeneous mix at startup (some zerocopy, some copy)
        // is a known multi-queue failure mode on several drivers: the
        // attached XDP program is in DRV/zerocopy mode but the queues
        // that fell back to copy mode silently drop redirects in the
        // kernel, so userspace sees zero packets while the kernel-side
        // xsk_hit counter still climbs.
        const bool requested_zc =
            (cfg.bind_flags & XDP_ZEROCOPY) != 0;
        xdp_options opts{};
        socklen_t opts_len = sizeof(opts);
        if (::getsockopt(rs.pfd.fd, SOL_XDP, XDP_OPTIONS,
                         &opts, &opts_len) == 0) {
            const bool got_zc =
                (opts.flags & XDP_OPTIONS_ZEROCOPY) != 0;
            if (got_zc) {
                g_bind_mode_zerocopy.fetch_add(1,
                                               std::memory_order_relaxed);
            } else {
                g_bind_mode_copy.fetch_add(1,
                                           std::memory_order_relaxed);
            }
            TCPLOG_DEBUG(
                "[xdp_bind] queue=%u mode=%s requested_zerocopy=%s",
                queue,
                got_zc ? "zerocopy" : "copy",
                requested_zc ? "true" : "false");
            if (requested_zc && !got_zc) {
                TCPLOG_WARN(
                    "[xdp_bind] queue=%u: requested zerocopy but kernel "
                    "granted copy mode. With multi-queue this is the most "
                    "common cause of 'kernel xsk_hit but userspace rx=0': "
                    "the attached XDP program runs in DRV (zerocopy) mode "
                    "and silently drops redirects to copy-mode sockets. "
                    "Ensure the driver supports zerocopy on every queue "
                    "served (e.g. mlx5: `ethtool -L %s combined %u`).",
                    queue, ifname.c_str(), impl.opts.queue_count);
            }
        } else {
            TCPLOG_DEBUG(
                "[xdp_bind] queue=%u: getsockopt(XDP_OPTIONS) failed: %s "
                "(unable to verify zerocopy/copy mode)",
                queue, std::strerror(errno));
        }

        return true;
    };

    // Install the AF_XDP socket fd into xsks_map at key=queue. This is the
    // handoff point: after this succeeds, bpf_redirect_map(&xsks_map, queue, ...)
    // inside the XDP program can deliver packets into our socket's RX ring.
    auto publish_xsk_socket = [&]() -> bool {
        const __u32 qkey = queue;

        // Preferred path: libxdp knows the queue the socket is bound to and
        // writes the right key. This handles NIC quirks libxdp is aware of.
        int xskmap_rc = xsk_socket__update_xskmap(rs.xsk, rs.xsks_fd);
        if (xskmap_rc != 0) {
            // Older libxdp versions on some kernels return a non-zero status
            // even after a successful write, so try a plain map update as a
            // defensive fallback before giving up.
            const int libxdp_errno = errno;
            const int xsk_fd = xsk_socket__fd(rs.xsk);
            if (bpf_map_update_elem(rs.xsks_fd, &qkey, &xsk_fd, BPF_ANY) != 0) {
                TCPLOG_ERROR(
                    "Failed to install AF_XDP socket into xsks_map for queue %u "
                    "(libxdp rc=%d errno=%s; bpf_map_update_elem errno=%s)",
                    queue,
                    xskmap_rc,
                    libxdp_errno ? std::strerror(libxdp_errno) : "n/a",
                    std::strerror(errno));
                return false;
            }
            TCPLOG_WARN(
                "libxdp xsks_map update returned rc=%d (errno=%s) for queue %u; "
                "fell back to bpf_map_update_elem successfully",
                xskmap_rc,
                libxdp_errno ? std::strerror(libxdp_errno) : "n/a",
                queue);
        }

        // Optional sanity check. Most kernels return -EOPNOTSUPP for userspace
        // lookups on BPF_MAP_TYPE_XSKMAP, so a failure here is informational,
        // not fatal. If the lookup *is* supported and returns an empty slot,
        // we abort: the map update above silently didn't stick.
        __u32 probe = 0;
        const int lrc = bpf_map_lookup_elem(rs.xsks_fd, &qkey, &probe);
        if (lrc == 0 && probe == 0) {
            TCPLOG_ERROR("xsks_map[queue=%u] lookup returned an empty slot "
                         "after update; the AF_XDP socket is not installed",
                         queue);
            return false;
        }
        if (lrc != 0 && errno != EOPNOTSUPP && errno != EINVAL) {
            TCPLOG_WARN("xsks_map lookup probe failed for queue %u: %s "
                        "(not fatal; continuing)",
                        queue, std::strerror(errno));
        }
        return true;
    };

    // Drop any pre-existing pinned maps from bpffs (used when we detect stale
    // layouts left over from an older OpenPenny build).
    auto remove_pins = [&]() {
        ::close(rs.conf_fd);
        ::close(rs.xsks_fd);
        ::close(rs.stats_fd);
        ::close(rs.settings_fd);
        rs.conf_fd = rs.xsks_fd = rs.stats_fd = rs.settings_fd = -1;
        (void)::unlink(impl.tuning.pin_conf_path.c_str());
        (void)::unlink(impl.tuning.pin_xsks_path.c_str());
        if (!impl.tuning.pin_stats_path.empty()) {
            (void)::unlink(impl.tuning.pin_stats_path.c_str());
        }
        if (!impl.tuning.pin_settings_path.empty()) {
            (void)::unlink(impl.tuning.pin_settings_path.c_str());
        }
    };

    // --- Step 2: locate the BPF maps --------------------------------------
    //
    // Three cases:
    //   a) Another queue worker on this interface is already up. We MUST
    //      reuse its pinned maps so we share the same xsks_map / conf /
    //      settings instance.
    //   b) reuse_pins is on and the pins exist. Use them, but validate the
    //      layout first so we don't silently mismatch older pinned maps.
    //   c) Otherwise, load the object fresh and (optionally) pin the maps
    //      so sibling workers can find them.

    const bool shared_reader_already_open = impl.shared_attach->refs > 0;
    bool pins_ok = false;
    if (shared_reader_already_open && open_maps_from_pins()) {
        pins_ok = true;
        rs.pinned_maps = true;
        rs.xdp_flags = impl.shared_attach->xdp_flags;
    } else if (impl.tuning.reuse_pins && open_maps_from_pins()) {
        bool stale_pins = false;
        bpf_map_info conf_info{};
        __u32 conf_info_len = sizeof(conf_info);
        if (bpf_obj_get_info_by_fd(rs.conf_fd, &conf_info, &conf_info_len) == 0 &&
            (conf_info.max_entries < xdp::kBpfMaxRules ||
             conf_info.value_size != xdp::kBpfMatchRuleValueSize)) {
            TCPLOG_ERROR("Pinned rule map at %s has stale layout "
                         "(entries=%u value_size=%u; need entries>=%u value_size=%u).",
                         impl.tuning.pin_conf_path.c_str(),
                         conf_info.max_entries,
                         conf_info.value_size,
                         xdp::kBpfMaxRules,
                         xdp::kBpfMatchRuleValueSize);
            stale_pins = true;
        }

        bpf_map_info settings_info{};
        __u32 settings_info_len = sizeof(settings_info);
        if (bpf_obj_get_info_by_fd(rs.settings_fd, &settings_info, &settings_info_len) == 0 &&
            settings_info.value_size != xdp::kBpfSettingsValueSize) {
            TCPLOG_ERROR("Pinned settings map at %s has stale layout "
                         "(value_size=%u; need value_size=%u).",
                         impl.tuning.pin_settings_path.c_str(),
                         settings_info.value_size,
                         xdp::kBpfSettingsValueSize);
            stale_pins = true;
        }

        // Pins were created by some prior process and the layout is good,
        // but is the program from that prior process still attached on
        // the netdev? If not, we'd silently inherit dead state: our maps
        // (including the stats map) would be readable but no XDP code is
        // running, so packets are never observed. Detect this and treat
        // it like a stale-layout case so we drop the pins and load fresh.
        if (!stale_pins) {
            __u32 prog_id = 0;
            const int qrc = bpf_xdp_query_id(rs.ifindex, 0, &prog_id);
            if (qrc == 0 && prog_id == 0) {
                TCPLOG_WARN("Pinned AF_XDP maps exist for %s but no XDP "
                            "program is currently attached on the "
                            "interface (likely from a prior process that "
                            "exited). Dropping pins and loading fresh.",
                            ifname.c_str());
                stale_pins = true;
            }
        }

        if (stale_pins) {
            remove_pins();
        } else {
            pins_ok = true;
            rs.pinned_maps = true;
        }
    } else if (shared_reader_already_open) {
        TCPLOG_ERROR("Pinned AF_XDP maps are not available for shared queue startup on %s.",
                     ifname.c_str());
        cleanup();
        return false;
    }

    if (!pins_ok) {
        rs.obj = bpf_object__open(impl.tuning.bpf_object.c_str());
        if (!rs.obj) {
            TCPLOG_ERROR("Failed to open BPF object %s", impl.tuning.bpf_object.c_str());
            cleanup();
            return false;
        }
        if (bpf_object__load(rs.obj)) {
            TCPLOG_ERROR("Failed to load BPF object %s", impl.tuning.bpf_object.c_str());
            cleanup();
            return false;
        }
        if (!open_maps_from_object(rs.obj)) {
            cleanup();
            return false;
        }
        if (impl.tuning.pin_maps) {
            if (!pin_maps()) {
                cleanup();
                return false;
            }
            rs.pinned_maps = true;
        }
    }

    if (rs.xdp_flags == 0) {
        rs.xdp_flags = impl.tuning.prefer_drv_mode ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    }

    // --- Step 3: publish pass-only defaults --------------------------------
    //
    // Before the XDP program starts evaluating packets, force its rule table
    // into a pass-only state. This is the safe default — it guarantees we
    // cannot accidentally blackhole or misredirect traffic during the brief
    // window between "program attached" and "xsks_map populated & real rules
    // published".

    // Worker 0 publishes pass-only defaults BEFORE attaching the program
    // so the BPF program never blackholes traffic during startup. The real
    // match rules are deferred to the LAST worker (see Step 6 below) so
    // every queue's xsks_map[N] entry is in place before redirects begin.
    const bool should_publish_pass_defaults =
        impl.tuning.update_conf_map && !shared_reader_already_open;
    if (should_publish_pass_defaults &&
        !xdp::program_xdp_pass_defaults(
            xdp::XdpRuleMapFds{rs.conf_fd, rs.settings_fd},
            impl.tuning.allow_ssh_bypass)) {
        cleanup();
        return false;
    }

    // --- Step 4: attach the XDP program ------------------------------------
    //
    // Only the first queue worker on an interface attaches; subsequent
    // workers reuse the already-attached program (pins_ok == true).

    if (!pins_ok && impl.tuning.attach_program && !attach_program()) {
        cleanup();
        return false;
    }

    // --- Step 5: UMEM, AF_XDP socket, and fill-ring priming ----------------

    if (!setup_umem()) {
        cleanup();
        return false;
    }

    if (!setup_socket()) {
        cleanup();
        return false;
    }

    // Prime the fill ring with every UMEM frame so the driver has somewhere
    // to place the very first packet. Without this the RX ring stays empty
    // forever — the driver needs descriptors posted BEFORE it starts RX.
    uint32_t idx = 0;
    const uint32_t primed = xsk_ring_prod__reserve(&rs.fq, rs.num_frames, &idx);
    if (primed > 0) {
        for (uint32_t i = 0; i < primed; ++i) {
            *xsk_ring_prod__fill_addr(&rs.fq, idx + i) = i * rs.frame_size;
        }
        xsk_ring_prod__submit(&rs.fq, primed);
        if (!wake_rx_if_needed(rs.xsk, rs.fq)) {
            cleanup();
            return false;
        }
        if (primed != rs.num_frames) {
            TCPLOG_WARN("AF_XDP fill ring primed with %u/%u frames", primed, rs.num_frames);
        }
    } else {
        TCPLOG_ERROR("AF_XDP fill ring reserve returned 0 during startup");
        cleanup();
        return false;
    }

    // --- Step 6: hand-off and activate match rules -------------------------
    //
    // Install the socket fd into xsks_map[queue] first; only then publish the
    // real redirect rules. This order guarantees the XDP program never issues
    // a redirect to a queue that has no live AF_XDP listener.

    if (!publish_xsk_socket()) {
        cleanup();
        return false;
    }

    // Real match rules are deferred to the last worker.
    //
    // Why: worker setup is serialised through shared_attach->mutex and
    // takes ~80-100 ms per worker (UMEM alloc + bind + fill-ring prime).
    // With queue_count=63 that's a 5+ second startup window. If worker 0
    // publishes the real rules during ITS open(), the BPF program starts
    // redirecting matched packets immediately — but only xsks_map[0] is
    // populated, so packets to queues 1..62 hit xsk_miss until each later
    // worker registers. We saw this in the wild: after a 9k-packet burst,
    // 2946 xsk_hit (queue 0) and 6213 xsk_miss (the rest).
    //
    // Fix: every worker publishes pass-only-defaults during worker 0's
    // open (so the program never blackholes), then the LAST worker swaps
    // to the real rules once every queue has registered its socket.
    //
    // "Last worker" check: we bump refs BEFORE the check so refs reflects
    // the total number of workers that have completed setup, including
    // this one. With queue_count=N, the worker that observes refs == N
    // after its own increment is the last and owns the rule swap.
    //
    // Transfer ownership of the attach from this reader to the shared
    // state first so the program stays attached if this worker closes
    // early, then bump refs and -- if we're last -- publish real rules.
    if (rs.attached) {
        impl.shared_attach->attached = true;
        impl.shared_attach->ifindex = rs.ifindex;
        impl.shared_attach->xdp_flags = rs.xdp_flags;
        rs.attached = false;
    }
    ++impl.shared_attach->refs;

    const unsigned expected_workers = std::max(1u, impl.opts.queue_count);
    const bool is_last_worker =
        impl.shared_attach->refs >= expected_workers;
    const bool should_publish_real_rules =
        impl.tuning.update_conf_map && is_last_worker;
    if (should_publish_real_rules) {
        // Zero the BPF stats map so the [xdp_counters] line that fires
        // every 5s reflects the CURRENT run only. Without this, any pins
        // left over from a previous run carry their accumulated counter
        // values forward and the operator sees stale numbers that look
        // suspiciously frozen. The map is BPF_MAP_TYPE_ARRAY with one
        // entry at key 0, value = struct stats from the BPF program.
        if (rs.stats_fd >= 0) {
            struct {
                std::uint64_t seen;
                std::uint64_t vlan;
                std::uint64_t ipv4;
                std::uint64_t ssh_pass;
                std::uint64_t match;
                std::uint64_t nomatch;
                std::uint64_t queue_mismatch;
                std::uint64_t xsk_hit;
                std::uint64_t xsk_miss;
                std::uint64_t redirect;
                std::uint64_t pass;
            } zero{};
            const __u32 k0 = 0;
            if (bpf_map_update_elem(rs.stats_fd, &k0, &zero, BPF_ANY) != 0) {
                TCPLOG_WARN("[openpenny] failed to zero kernel stats map: %s "
                            "(non-fatal; counters may carry over from a "
                            "previous run)",
                            std::strerror(errno));
            }
        }

        TCPLOG_INFO("[openpenny] all %u queue workers registered "
                    "(AF_XDP sockets bound) — activating live match rules",
                    expected_workers);
        if (!update_match_maps()) {
            cleanup();
            return false;
        }
        // Clear, single-line confirmation that everything is wired up
        // and packets matching the policy will now be redirected to
        // userspace. This is the line operators should look for to know
        // the run is healthy and ready to receive traffic.
        const unsigned q_first = impl.opts.base_queue;
        const unsigned q_last  = impl.opts.base_queue + expected_workers - 1;
        TCPLOG_INFO("[openpenny] ====== READY ====== traffic redirection "
                    "is now ACTIVE on '%s' queues %u-%u (%u worker%s)",
                    ifname.c_str(),
                    q_first, q_last,
                    expected_workers,
                    expected_workers == 1 ? "" : "s");
    }

    // Run the RSS coverage check exactly once per interface. Done AFTER the
    // pipeline is fully wired so the log line reflects the final served set
    // and the operator gets a single authoritative message instead of one per
    // queue worker.
    if (!impl.shared_attach->rss_checked) {
        impl.shared_attach->rss_checked = true;
        check_rss_coverage(ifname);
    }

    opened_ = true;
    return true;
#endif
}

void XdpReader::close() {
#ifdef OPENPENNY_WITH_LIBBPF
    if (!impl_) return;
    auto shared_attach = impl_->shared_attach;
    const auto shared_key = impl_->shared_attach_key;
    std::unique_lock<std::mutex> shared_lock;
    if (shared_attach) {
        shared_lock = std::unique_lock<std::mutex>(shared_attach->mutex);
    }
    Impl::RealState& rs = impl_->real;
    // Clear xsks_map entry for this queue if possible to avoid stale FDs on restart.
    if (rs.xsks_fd >= 0) {
        __u32 key = impl_->queue;
        bpf_map_delete_elem(rs.xsks_fd, &key);
    }
    if (rs.xsk) { xsk_socket__delete(rs.xsk); rs.xsk = nullptr; }
    if (rs.umem) { xsk_umem__delete(rs.umem); rs.umem = nullptr; }
    if (rs.umem_area) { std::free(rs.umem_area); rs.umem_area = nullptr; }
    if (rs.conf_fd >= 0) { ::close(rs.conf_fd); rs.conf_fd = -1; }
    if (rs.xsks_fd >= 0) { ::close(rs.xsks_fd); rs.xsks_fd = -1; }
    if (rs.stats_fd >= 0) { ::close(rs.stats_fd); rs.stats_fd = -1; }
    if (rs.settings_fd >= 0) { ::close(rs.settings_fd); rs.settings_fd = -1; }
    if (rs.obj) { bpf_object__close(rs.obj); rs.obj = nullptr; }
    if (shared_attach && shared_attach->refs > 0) {
        --shared_attach->refs;
        if (shared_attach->refs == 0 &&
            shared_attach->attached &&
            impl_->tuning.detach_on_close) {
            bpf_xdp_detach(shared_attach->ifindex, shared_attach->xdp_flags, nullptr);
            shared_attach->attached = false;
        }
    }
    if (shared_lock.owns_lock()) {
        shared_lock.unlock();
    }
    if (shared_attach) {
        release_shared_attach_state(shared_key, shared_attach);
    }
    impl_->shared_attach.reset();
    impl_->shared_attach_key.clear();
#endif
    opened_ = false;
}

#ifdef OPENPENNY_WITH_LIBBPF
// Verify the NIC's RSS indirection table only routes to queues we serve.
//
// Symptom this prevents: "xsk_miss on ~(N-1)/N of matched packets" when the NIC
// has N RX queues, RSS spreads across all of them, but OpenPenny only opened
// AF_XDP sockets on a subset.
//
// Served set = {base_queue, base_queue + 1, ..., base_queue + queue_count - 1}
// (see Config::queue_base / queue_count and OpenpennyPipelineDriver's worker layout).
//
// Three outcomes:
//   - RSS targets a strict subset of served queues -> OK (INFO)
//   - RSS table unreadable (virtual NIC, loopback, no ethtool support) -> INFO skip
//   - RSS targets queues we don't serve              -> WARN with actionable fix
void XdpReader::check_rss_coverage(const std::string& ifname) {
    if (!impl_) return;
    const auto& opts = impl_->opts;
    const unsigned qcount = std::max(1u, opts.queue_count);

    auto indir = read_rss_indir_table(ifname);
    if (!indir) {
        TCPLOG_INFO("[rss_check] %s: RSS indirection unreadable "
                    "(likely virtual/loopback NIC); skipping coverage check.",
                    ifname.c_str());
        return;
    }

    // Build the set of queues actually referenced by the RSS table, and the
    // set we've bound AF_XDP sockets to.
    std::set<std::uint32_t> rss_queues(indir->begin(), indir->end());
    std::set<std::uint32_t> served;
    for (unsigned i = 0; i < qcount; ++i) {
        served.insert(opts.base_queue + i);
    }

    std::set<std::uint32_t> unserved;
    for (auto q : rss_queues) {
        if (served.find(q) == served.end()) unserved.insert(q);
    }

    auto format_set = [](const std::set<std::uint32_t>& s) {
        std::ostringstream oss;
        oss << "{";
        bool first = true;
        for (auto q : s) {
            if (!first) oss << ",";
            oss << q;
            first = false;
        }
        oss << "}";
        return oss.str();
    };

    if (unserved.empty()) {
        TCPLOG_INFO("[rss_check] %s OK: RSS steers to queues %s; "
                    "AF_XDP sockets bound to %s (table size=%zu).",
                    ifname.c_str(),
                    format_set(rss_queues).c_str(),
                    format_set(served).c_str(),
                    indir->size());
        return;
    }

    // Build a concrete one-liner the operator can run to fix it.
    // Prefer the weight form; `equal 1` is rejected on some drivers (mlx5).
    std::ostringstream fix;
    fix << "sudo ethtool -X " << ifname << " weight";
    const std::uint32_t max_q = *std::max_element(rss_queues.begin(), rss_queues.end());
    for (std::uint32_t q = 0; q <= max_q; ++q) {
        fix << ' ' << (served.count(q) ? 1 : 0);
    }

    TCPLOG_WARN("[rss_check] %s: RSS routes to queues %s but OpenPenny only serves %s. "
                "Approximately %zu of every %zu matched packets will hit xsk_miss.",
                ifname.c_str(),
                format_set(rss_queues).c_str(),
                format_set(served).c_str(),
                rss_queues.size() - (rss_queues.size() - unserved.size()),
                rss_queues.size());
    TCPLOG_WARN("[rss_check] fix options:");
    TCPLOG_WARN("[rss_check]   (1) restrict RSS to served queues:  %s", fix.str().c_str());
    TCPLOG_WARN("[rss_check]   (2) OR widen queue_count in config to cover %s and restart.",
                format_set(rss_queues).c_str());
}
#endif

#ifdef OPENPENNY_WITH_LIBBPF
// Describe the state of the XDP counters map (best-effort diagnostics).
// When a user reports "AF_XDP opens but no packets arrive" the counters
// tell us immediately which stage is dropping traffic:
//   seen==0            -> XDP program is not actually receiving packets
//                         (wrong interface, wrong attach mode, RSS sprays
//                         traffic to another queue, etc.)
//   seen>0, match==0   -> XDP runs but no rule matched — check traffic_match
//   match>0, xsk_miss>0 -> rule matched but xsks_map entry missing
//   queue_mismatch>0   -> rule targeted a queue the socket isn't bound to
//   xsk_hit>0, redirect>0 -> packets successfully redirected to AF_XDP
void XdpReader::log_xdp_counters_if_due() {
    if (!impl_) return;
    auto& rs = impl_->real;
    if (rs.stats_fd < 0) return;

    // The XDP stats map is shared across all workers (single PERCPU_ARRAY of
    // global counters), so we only need ONE worker to print it per interval.
    // We dedupe with a process-wide atomic timestamp: the first worker to
    // win the CAS for the next 5-second window owns the print; the rest skip.
    using Clock = std::chrono::steady_clock;
    static std::atomic<Clock::rep> g_next_log_ns{0};
    const auto now = Clock::now();
    const auto now_ns = now.time_since_epoch().count();
    auto next = g_next_log_ns.load(std::memory_order_relaxed);
    if (now_ns < next) return;
    const auto new_next = (now + std::chrono::seconds(5)).time_since_epoch().count();
    if (!g_next_log_ns.compare_exchange_strong(next, new_next,
                                               std::memory_order_acq_rel)) {
        return;
    }
    rs.last_counter_log = now;

    // The counters map is BPF_MAP_TYPE_ARRAY with one entry, but its value is
    // a set of __u64 counters. Matches the layout of `struct stats` in
    // xdp_redirect_openpenny.c exactly.
    struct KernelStats {
        std::uint64_t seen;
        std::uint64_t vlan;
        std::uint64_t ipv4;
        std::uint64_t ssh_pass;
        std::uint64_t match;
        std::uint64_t nomatch;
        std::uint64_t queue_mismatch;
        std::uint64_t xsk_hit;
        std::uint64_t xsk_miss;
        std::uint64_t redirect;
        std::uint64_t pass;
    } stats{};

    const __u32 key = 0;
    if (bpf_map_lookup_elem(rs.stats_fd, &key, &stats) != 0) {
        return;
    }

    TCPLOG_INFO("[xdp_counters] seen=%llu ipv4=%llu match=%llu nomatch=%llu "
                "redirect=%llu xsk_hit=%llu xsk_miss=%llu queue_mismatch=%llu "
                "pass=%llu ssh_pass=%llu",
                (unsigned long long)stats.seen,
                (unsigned long long)stats.ipv4,
                (unsigned long long)stats.match,
                (unsigned long long)stats.nomatch,
                (unsigned long long)stats.redirect,
                (unsigned long long)stats.xsk_hit,
                (unsigned long long)stats.xsk_miss,
                (unsigned long long)stats.queue_mismatch,
                (unsigned long long)stats.pass,
                (unsigned long long)stats.ssh_pass);

    // Userspace mirror: how many of the kernel-redirected packets actually
    // surfaced through xsk_ring_cons__peek and survived PacketParser::decode.
    // Diagnostic crib:
    //   userspace_rx == 0  while xsk_hit > 0   -> RX ring never drained (kernel
    //                                              redirect failed at runtime
    //                                              or socket bound to wrong
    //                                              queue; check ring sizes
    //                                              vs. frame budget).
    //   decode_fail >> 0   close to userspace_rx -> PacketParser rejecting
    //                                              every frame (non-IPv4 RX,
    //                                              VLAN double-tag, etc.).
    //   peek_zero == poll_calls and userspace_rx == 0 -> driver never produced
    //                                              any RX descriptors (no
    //                                              traffic on this queue,
    //                                              wakeup race, or missing
    //                                              fill-ring frames).
    const std::uint64_t userspace_rx =
        g_userspace_rx_packets.load(std::memory_order_relaxed);
    const std::uint64_t userspace_decode_fail =
        g_userspace_decode_failures.load(std::memory_order_relaxed);
    const std::uint64_t userspace_peek_zero =
        g_userspace_peek_zero.load(std::memory_order_relaxed);
    const std::uint64_t userspace_poll_calls =
        g_userspace_poll_calls.load(std::memory_order_relaxed);
    TCPLOG_DEBUG("[xdp_userspace] rx=%llu decode_fail=%llu peek_zero=%llu "
                 "poll_calls=%llu (kernel xsk_hit=%llu)",
                 (unsigned long long)userspace_rx,
                 (unsigned long long)userspace_decode_fail,
                 (unsigned long long)userspace_peek_zero,
                 (unsigned long long)userspace_poll_calls,
                 (unsigned long long)stats.xsk_hit);

    // Per-socket kernel-side stats summed across every queue worker. If
    // every value is 0 while xsk_hit is non-zero, the kernel never even
    // reached the AF_XDP socket — i.e. bpf_redirect_map(&xsks_map, qid, ...)
    // is failing at the kernel boundary (queue/dev mismatch, or attached
    // program references a different xsks_map than the one our sockets
    // registered into).
    TCPLOG_DEBUG("[xdp_socket_stats] rx_dropped=%llu rx_invalid=%llu "
                 "rx_ring_full=%llu rx_fill_empty=%llu",
                 (unsigned long long)g_xdp_stats_rx_dropped.load(
                     std::memory_order_relaxed),
                 (unsigned long long)g_xdp_stats_rx_invalid.load(
                     std::memory_order_relaxed),
                 (unsigned long long)g_xdp_stats_rx_ring_full.load(
                     std::memory_order_relaxed),
                 (unsigned long long)g_xdp_stats_rx_fq_empty.load(
                     std::memory_order_relaxed));

    // Heterogeneous-mode warning. Promoted to INFO so the operator sees it
    // even at the default log level: this is the single-most-likely
    // explanation for "xsk_hit > 0 but userspace_rx == 0" with multi-queue
    // and we want to surface it without forcing them to enable DEBUG.
    const std::uint32_t zc_count =
        g_bind_mode_zerocopy.load(std::memory_order_relaxed);
    const std::uint32_t cp_count =
        g_bind_mode_copy.load(std::memory_order_relaxed);
    if (zc_count > 0 && cp_count > 0) {
        TCPLOG_INFO(
            "[xdp_bind] heterogeneous bind modes detected: %u queue(s) in "
            "zerocopy, %u in copy. Mixed-mode multi-queue is the most "
            "common cause of silent redirect failures in the kernel.",
            zc_count, cp_count);
    } else if (zc_count > 0) {
        TCPLOG_DEBUG("[xdp_bind] all %u queue(s) in zerocopy mode",
                     zc_count);
    } else if (cp_count > 0) {
        TCPLOG_DEBUG("[xdp_bind] all %u queue(s) in copy mode",
                     cp_count);
    }
}
#endif

// Drain up to `budget` packets from the AF_XDP RX ring, dispatch each to
// `handler`, and return every consumed frame back to the fill ring so the
// driver has buffers to fill with new RX.
//
// Polling model:
//   * poll_timeout_ms == 0 -> non-blocking. We do one short poll() to give
//     the kernel a chance to drain NAPI for us, but we never block. Caller
//     is expected to spin.
//   * poll_timeout_ms > 0  -> blocking with timeout. We wait up to N ms
//     for POLLIN before peeking, which is more CPU-friendly.
bool XdpReader::poll(const net::PacketHandler& handler, std::size_t budget) {
#ifndef OPENPENNY_WITH_LIBBPF
    (void)handler;
    (void)budget;
    TCPLOG_ERROR("libbpf support missing: install libbpf/libbpf-dev "
                 "(or your distro equivalent) and rebuild openpenny.");
    return false;
#else
    auto& rs = impl_->real;
    if (!rs.ready || !rs.xsk) return false;

    const std::size_t max_batch = budget ? std::max<std::size_t>(budget, impl_->opts.batch)
                                         : impl_->opts.batch;
    const int poll_timeout = static_cast<int>(impl_->opts.poll_timeout_ms);
    std::size_t processed = 0;

    g_userspace_poll_calls.fetch_add(1, std::memory_order_relaxed);

    while (processed < max_batch) {
        // Give the driver a chance to run NAPI and move frames into our RX
        // ring. In busy-poll mode (timeout == 0) this is effectively a
        // yield; with a positive timeout it's a proper block.
        (void)::poll(&rs.pfd, 1, poll_timeout);

        uint32_t idx_rx = 0;
        const uint32_t want = static_cast<uint32_t>(max_batch - processed);
        uint32_t rcvd = xsk_ring_cons__peek(&rs.rx, want, &idx_rx);

        if (!rcvd) {
            // No frames yet. If NEED_WAKEUP is set and the driver is idle,
            // poke it via recvfrom() so it starts servicing the rings. Then
            // peek one more time before deciding to bail.
            wake_rx_if_needed(rs.xsk, rs.fq);
            rcvd = xsk_ring_cons__peek(&rs.rx, want, &idx_rx);
            if (!rcvd) {
                g_userspace_peek_zero.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }

        g_userspace_rx_packets.fetch_add(rcvd, std::memory_order_relaxed);
        const std::uint64_t decode_failures_before = rs.decode_failures;

        // Reserve slots in the fill ring up front so we can return each
        // consumed frame address after dispatching its packet. If we can't
        // get the whole batch at once we fall back to one-at-a-time refills.
        uint32_t refill_idx = 0;
        const uint32_t reserved = xsk_ring_prod__reserve(&rs.fq, rcvd, &refill_idx);
        const bool bulk_refill = (reserved == rcvd);

        for (uint32_t i = 0; i < rcvd; ++i) {
            const xdp_desc* desc = xsk_ring_cons__rx_desc(&rs.rx, idx_rx + i);
            const uint64_t addr = desc->addr;
            const uint32_t len  = desc->len;

            const uint8_t* pkt = static_cast<const uint8_t*>(rs.umem_area) +
                                 (addr & XSK_UNALIGNED_BUF_ADDR_MASK);
            ++rs.rx_packets;

            net::PacketView packet{};
            if (net::PacketParser::decode(pkt, len, packet)) {
                packet.timestamp_ns = now_ns();
                handler(packet);
            } else {
                ++rs.decode_failures;
            }

            // Return the frame to the kernel so it can refill it.
            if (bulk_refill) {
                *xsk_ring_prod__fill_addr(&rs.fq, refill_idx + i) = addr;
            } else {
                uint32_t single_idx = 0;
                if (xsk_ring_prod__reserve(&rs.fq, 1, &single_idx) == 1) {
                    *xsk_ring_prod__fill_addr(&rs.fq, single_idx) = addr;
                    xsk_ring_prod__submit(&rs.fq, 1);
                    wake_rx_if_needed(rs.xsk, rs.fq);
                }
            }
        }

        if (bulk_refill) {
            xsk_ring_prod__submit(&rs.fq, rcvd);
            wake_rx_if_needed(rs.xsk, rs.fq);
        }

        xsk_ring_cons__release(&rs.rx, rcvd);
        processed += rcvd;

        const std::uint64_t decode_failures_delta =
            rs.decode_failures - decode_failures_before;
        if (decode_failures_delta) {
            g_userspace_decode_failures.fetch_add(
                decode_failures_delta, std::memory_order_relaxed);
        }

        // When caller passes budget==0 we only poll once per call.
        if (!budget) break;

        // Local per-queue metrics (frame-level). With many queues this log
        // line fires from every worker so we keep it at DEBUG; operators who
        // need it can flip the log level. The aggregate XDP counters dumped
        // by log_xdp_counters_if_due() below give the cross-queue view.
        if (TCPLOG_ENABLED(DEBUG)) {
            auto now = std::chrono::steady_clock::now();
            const bool first_log = rs.last_queue_log.time_since_epoch().count() == 0;
            if (first_log || now - rs.last_queue_log >= std::chrono::seconds(5)) {
                const uint32_t fq_free = xsk_prod_nb_free(&rs.fq, rs.num_frames);
                rs.last_queue_log = now;
                TCPLOG_DEBUG(
                    "[xdp_queue=%u] rx_batch=%u rx_total=%llu decode_failures=%llu "
                    "rx_ring=%u fq_free=%u fq_cap=%u",
                    impl_->queue,
                    rcvd,
                    (unsigned long long)rs.rx_packets,
                    (unsigned long long)rs.decode_failures,
                    impl_->opts.rx_ring,
                    fq_free,
                    rs.num_frames);
            }
        }
    }

    // Sample this socket's per-queue kernel-side XDP statistics no more than
    // every 5 seconds and accumulate the deltas into the process-wide atomics.
    // We do it inside poll() (instead of open/close) because (a) sockets can
    // accumulate stats over the run and (b) it lets the same dedup CAS in
    // log_xdp_counters_if_due() emit a self-consistent cross-queue snapshot.
    {
        const auto stats_now = std::chrono::steady_clock::now();
        const bool first_sample = rs.last_xdp_stats_sample.time_since_epoch().count() == 0;
        if (first_sample ||
            stats_now - rs.last_xdp_stats_sample >= std::chrono::seconds(5)) {
            rs.last_xdp_stats_sample = stats_now;
            xdp_statistics st{};
            socklen_t st_len = sizeof(st);
            if (::getsockopt(xsk_socket__fd(rs.xsk),
                             SOL_XDP, XDP_STATISTICS,
                             &st, &st_len) == 0) {
                auto bump_delta =
                    [](std::atomic<std::uint64_t>& acc,
                       std::uint64_t& last,
                       std::uint64_t curr) {
                        if (curr >= last) {
                            const std::uint64_t delta = curr - last;
                            if (delta) {
                                acc.fetch_add(delta,
                                              std::memory_order_relaxed);
                            }
                        }
                        last = curr;
                    };
                bump_delta(g_xdp_stats_rx_dropped,
                           rs.last_rx_dropped, st.rx_dropped);
                bump_delta(g_xdp_stats_rx_invalid,
                           rs.last_rx_invalid, st.rx_invalid_descs);
                bump_delta(g_xdp_stats_rx_ring_full,
                           rs.last_rx_ring_full, st.rx_ring_full);
                bump_delta(g_xdp_stats_rx_fq_empty,
                           rs.last_rx_fq_empty,
                           st.rx_fill_ring_empty_descs);
            }
        }
    }

    // Kernel-side XDP verdict counters (ties the user-visible symptom
    // "no packets" to a specific stage: not seen / not matched / redirected
    // but socket missing / etc.).
    log_xdp_counters_if_due();

    return true;
#endif
}

} // namespace openpenny
