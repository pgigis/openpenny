// SPDX-License-Identifier: MIT
// AF_XDP user app (diagnostic build) with TUN reinjection:
// - RX (from XDP redirect) → (optional print) → (TX back out | write L3 to TUN) or DROP
// - Writes {prefix,mask,qid} to 'conf' (qid must equal --queue)
// - Pins maps so --no-attach can reuse them
// - --copy forces copy mode (disables zerocopy)
// - --verbose logs socket creation, map update, and 1s RX/TX counters
//
// Usage example (reinject to kernel via TUN):
//   sudo ip tuntap add dev xdp-tun mode tun
//   sudo ip link set xdp-tun up
//   sudo ./xsk_print_forward --if ens5f1np1.41 --queue 0 --prefix 192.168.41.2 --mask 32 --tun xdp-tun --verbose

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>
#include <chrono>

// Pinned bpffs map locations (must match your XDP program)
static const char* PIN_CONF = "/sys/fs/bpf/xdp_fw_conf";   // ARRAY map: key 0 -> {prefix,mask,qid}
static const char* PIN_XSKS = "/sys/fs/bpf/xdp_fw_xsks";   // XSKMAP:   key qid -> xsk fd

struct Args {
    std::string ifname;      // interface name for RX/TX XSK
    int         queue   = 0; // RX/TX queue index to bind
    uint32_t    prefix  = 0; // host-order IPv4 prefix to match (configured into 'conf' map)
    uint32_t    mask    = 0; // host-order mask (/bits -> mask)
    int         hexdump = 0; // bytes to hexdump per packet (0 = none)
    int         batch   = 64;
    bool        no_print   = false;
    bool        no_attach  = false;
    bool        drop       = false;   // default action: false => TX, true => DROP
    bool        force_copy = false;   // --copy forces copy mode
    bool        verbose    = false;

    // NEW: TUN reinjection
    std::string tun_name;      // e.g., "xdp-tun"
    bool        reinject_tun = false;
};

static void usage(const char* p) {
    fprintf(stderr,
        "Usage: %s --if IFACE --queue Q --prefix A.B.C.D --mask BITS "
        "[--hexdump BYTES] [--batch N] [--no-print] [--no-attach] "
        "[--action tx|drop] [--copy] [--verbose] [--tun NAME]\n", p);
}

static uint32_t parse_ip(const char* s) {
    in_addr a{};
    if (inet_pton(AF_INET, s, &a) != 1) { fprintf(stderr, "Bad IPv4: %s\n", s); exit(1); }
    return ntohl(a.s_addr);
}

static uint32_t mask_from_bits(int bits) {
    if (bits <= 0)  return 0;
    if (bits >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - bits);
}

static void parse_args(int argc, char** argv, Args& a) {
    for (int i=1;i<argc;i++) {
        std::string k = argv[i];
        if ((k=="--if"||k=="-i") && i+1<argc) a.ifname = argv[++i];
        else if (k=="--queue"  && i+1<argc)   a.queue  = atoi(argv[++i]);
        else if (k=="--prefix" && i+1<argc)   a.prefix = parse_ip(argv[++i]);
        else if (k=="--mask"   && i+1<argc)   a.mask   = mask_from_bits(atoi(argv[++i]));
        else if (k=="--hexdump"&& i+1<argc)   a.hexdump= atoi(argv[++i]);
        else if (k=="--batch"  && i+1<argc)   a.batch  = atoi(argv[++i]);
        else if (k=="--no-print")             a.no_print = true;
        else if (k=="--no-attach")            a.no_attach = true;
        else if (k=="--action" && i+1<argc) {
            std::string v = argv[++i];
            if      (v == "tx")   a.drop = false;
            else if (v == "drop") a.drop = true;
            else { fprintf(stderr, "--action must be tx|drop\n"); exit(1); }
        } else if (k=="--copy")               a.force_copy = true;
        else if (k=="--verbose")              a.verbose = true;
        else if ((k=="--tun"||k=="--tun-name") && i+1<argc) {
            a.tun_name = argv[++i]; a.reinject_tun = true;
        } else { usage(argv[0]); exit(1); }
    }
    if (a.ifname.empty() || a.prefix==0 || a.mask==0) { usage(argv[0]); exit(1); }
}

static void bump_memlock() {
    rlimit r{RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) perror("setrlimit MEMLOCK");
}

static int get_pinned_map_fds(int& conf_fd, int& xsks_fd) {
    conf_fd = bpf_obj_get(PIN_CONF);
    if (conf_fd < 0) return -1;
    xsks_fd = bpf_obj_get(PIN_XSKS);
    if (xsks_fd < 0) { close(conf_fd); return -1; }
    return 0;
}

static void pin_map_if_needed(struct bpf_map* m, const char* path) {
    if (bpf_map__pin(m, path)) {
        if (errno != EEXIST) { perror("bpf_map__pin"); exit(1); }
    }
}

static void set_prefix_fd(int conf_fd, uint32_t prefix, uint32_t mask, uint32_t qid) {
    uint32_t key = 0;
    struct { uint32_t prefix, mask, qid; } val{prefix, mask, qid};
    if (bpf_map_update_elem(conf_fd, &key, &val, BPF_ANY)) {
        perror("bpf_map_update_elem(conf)"); exit(1);
    }
}

static void bind_xsk_to_map_fd(int xsks_fd, int qid, int xsk_fd) {
    if (bpf_map_update_elem(xsks_fd, &qid, &xsk_fd, BPF_ANY)) {
        perror("bpf_map_update_elem(xsks_map)"); exit(1);
    }
}

// TUN helper (L3, no extra PI header)
static int tun_alloc(const char* name) {
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr{}; memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    return fd;
}

int main(int argc, char** argv) {
    Args args; parse_args(argc, argv, args);
    bump_memlock();
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int ifindex = if_nametoindex(args.ifname.c_str());
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    // Open or attach XDP + pin maps
    int conf_fd = -1, xsks_fd = -1;
    bpf_object*  obj  = nullptr;
    bpf_program* prog = nullptr;

    if (args.no_attach) {
        if (get_pinned_map_fds(conf_fd, xsks_fd) < 0) {
            fprintf(stderr, "Pinned maps not found. Attach once without --no-attach first.\n");
            return 1;
        }
        if (args.verbose) fprintf(stderr, "[v] Reusing pinned maps: conf=%s xsks=%s\n", PIN_CONF, PIN_XSKS);
    } else {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);

        obj = bpf_object__open_file("xdp_redirect_dstprefix.o", nullptr);
        if (!obj) { perror("bpf_object__open_file"); return 1; }
        if (bpf_object__load(obj)) { perror("bpf_object__load"); return 1; }

        prog = bpf_object__find_program_by_name(obj, "xdp_redirect_dstprefix");
        if (!prog) { fprintf(stderr, "program 'xdp_redirect_dstprefix' not found\n"); return 1; }

        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) { perror("bpf_program__fd"); return 1; }
        int flags = XDP_FLAGS_DRV_MODE;
        int err = bpf_xdp_attach(ifindex, prog_fd, flags, nullptr);
        if (err) { errno = -err; perror("bpf_xdp_attach(DRV_MODE)"); return 1; }
        if (args.verbose) fprintf(stderr, "[v] Attached native XDP program fd=%d on %s\n", prog_fd, args.ifname.c_str());

        bpf_map* mconf = bpf_object__find_map_by_name(obj, "conf");
        bpf_map* mxsks = bpf_object__find_map_by_name(obj, "xsks_map");
        if (!mconf || !mxsks) { fprintf(stderr, "maps not found in object\n"); return 1; }
        pin_map_if_needed(mconf, PIN_CONF);
        pin_map_if_needed(mxsks, PIN_XSKS);
        conf_fd = bpf_map__fd(mconf);
        xsks_fd = bpf_map__fd(mxsks);
        if (args.verbose) fprintf(stderr, "[v] Pinned maps at %s and %s\n", PIN_CONF, PIN_XSKS);
    }

    set_prefix_fd(conf_fd, args.prefix, args.mask, (uint32_t)args.queue);
    if (args.verbose) fprintf(stderr, "[v] conf: prefix=%u mask=%u qid=%d\n", args.prefix, args.mask, args.queue);

    // Optional: open TUN for reinjection
    int tun_fd = -1;
    if (args.reinject_tun) {
        if (args.tun_name.empty()) { fprintf(stderr, "--tun requires a device name\n"); return 1; }
        tun_fd = tun_alloc(args.tun_name.c_str());
        if (tun_fd < 0) { fprintf(stderr, "failed to open TUN %s\n", args.tun_name.c_str()); return 1; }
        if (args.verbose) fprintf(stderr, "[v] TUN open: %s fd=%d\n", args.tun_name.c_str(), tun_fd);
    }

    // === UMEM ===
    constexpr uint32_t FRAME_SIZE = 2048;
    constexpr uint32_t NUM_FRAMES = 4096;
    constexpr uint64_t UMEM_SIZE  = (uint64_t)FRAME_SIZE * NUM_FRAMES;

    void* umem_area = nullptr;
    if (posix_memalign(&umem_area, getpagesize(), UMEM_SIZE)) { perror("posix_memalign"); return 1; }
    memset(umem_area, 0, UMEM_SIZE);

    xsk_umem*     umem = nullptr;
    xsk_ring_prod fq{};
    xsk_ring_cons cq{};
    xsk_umem_config ucfg{};
    ucfg.fill_size      = NUM_FRAMES;
    ucfg.comp_size      = NUM_FRAMES;
    ucfg.frame_size     = FRAME_SIZE;
    ucfg.frame_headroom = 0;

    int ret = xsk_umem__create(&umem, umem_area, UMEM_SIZE, &fq, &cq, &ucfg);
    if (ret) { fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret)); return 1; }
    if (args.verbose) fprintf(stderr, "[v] UMEM created: %u frames x %u bytes\n", NUM_FRAMES, FRAME_SIZE);

    // === AF_XDP socket (RX+TX) ===
    xsk_socket*     xsk = nullptr;
    xsk_ring_cons   rx{};
    xsk_ring_prod   tx{};
    xsk_socket_config sc{};
    sc.rx_size      = NUM_FRAMES;
    sc.tx_size      = NUM_FRAMES;
    sc.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    sc.xdp_flags    = 0;
    sc.bind_flags   = 0;

    if (!args.force_copy) {
#ifdef XDP_ZEROCOPY
        sc.bind_flags |= XDP_ZEROCOPY;    // request driver-supported zerocopy (fast path)
#endif
    } else {
#ifdef XDP_COPY
        sc.bind_flags |= XDP_COPY;        // explicit copy-mode request (--copy flag)
#endif
    }

    ret = xsk_socket__create(&xsk, args.ifname.c_str(), args.queue, umem, &rx, &tx, &sc);
    fprintf(stderr, "[v] xsk_socket__create ret=%d (%s)\n", ret, ret?strerror(-ret):"OK");
    if (ret) {
        if (ret == -EINVAL || ret == -ENOTSUP)
            fprintf(stderr, "Hint: try --copy or a different --queue (driver/queue may not support ZC).\n");
        return 1;
    }

    // Prime fill ring
    uint32_t idx;
    int reserved = xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx);
    for (int i=0; i<reserved; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = (uint64_t)i * FRAME_SIZE;
    if (reserved > 0) xsk_ring_prod__submit(&fq, reserved);
    if (args.verbose) fprintf(stderr, "[v] Fill ring primed with %d frames\n", reserved);

    // xsks_map[qid] = xskfd
    int xskfd = xsk_socket__fd(xsk);
    int up = bpf_map_update_elem(xsks_fd, &args.queue, &xskfd, BPF_ANY);
    fprintf(stderr, "[v] xsks_map[%d] <- fd=%d update ret=%d (%s)\n",
            args.queue, xskfd, up, up?strerror(errno):"OK");
    if (up) return 1;

    printf("AF_XDP on %s q=%d; hexdump=%d; batch=%d; action=%s; mode=%s; reinject=%s\n",
           args.ifname.c_str(), args.queue, args.hexdump, args.batch,
           args.drop ? "DROP" : "TX",
           args.force_copy ? "copy" : "zc-requested",
           args.reinject_tun ? args.tun_name.c_str() : "off");

    pollfd pfd{ xsk_socket__fd(xsk), POLLIN, 0 };
    uint64_t rx_pkts=0, tx_pkts=0, drops=0;
    auto last = std::chrono::steady_clock::now();

    while (true) {
        poll(&pfd, 1, 50);

        uint32_t idx_rx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(&rx, args.batch, &idx_rx);

        if (!rcvd && args.verbose) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last).count() >= 1) {
                fprintf(stderr, "[v] idle: rx=%llu tx=%llu drop=%llu\n",
                        (unsigned long long)rx_pkts, (unsigned long long)tx_pkts, (unsigned long long)drops);
                last = now;
            }
        }
        if (!rcvd) continue;

        // If we're NOT using TUN, reserve TX ring up-front (best effort)
        uint32_t idx_tx = 0;
        uint32_t reserved_tx = 0;
        if (!args.reinject_tun)
            reserved_tx = xsk_ring_prod__reserve(&tx, rcvd, &idx_tx);

        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc* rxd = xsk_ring_cons__rx_desc(&rx, idx_rx + i);
            uint64_t addr = rxd->addr;
            uint32_t len  = rxd->len;
            uint8_t* pkt  = (uint8_t*)umem_area + (addr & XSK_UNALIGNED_BUF_ADDR_MASK);
            rx_pkts++;

            // Optional print
            if (!args.no_print && len >= 34) {
                uint16_t eth_type = (pkt[12] << 8) | pkt[13];
                if (eth_type == 0x0800 || eth_type == 0x8100) {
                    // Best-effort IPv4 summary (no deep VLAN handling for print)
                    if (eth_type == 0x0800) {
                        uint8_t ihl = (pkt[14] & 0x0f) * 4;
                        if (14 + ihl + 4 <= len) {
                            uint32_t s = *(uint32_t*)(pkt + 26);
                            uint32_t d = *(uint32_t*)(pkt + 30);
                            char src[64], dst[64];
                            in_addr sa{ *(in_addr*)&s }, da{ *(in_addr*)&d };
                            inet_ntop(AF_INET, &sa, src, sizeof(src));
                            inet_ntop(AF_INET, &da, dst, sizeof(dst));
                            uint8_t  proto = pkt[23];
                            uint16_t sport=0, dport=0;
                            if (proto==6 || proto==17) {
                                sport = (pkt[14+ihl]   << 8) | pkt[14+ihl+1];
                                dport = (pkt[14+ihl+2] << 8) | pkt[14+ihl+3];
                            }
                            printf("%s %s:%u -> %s:%u len=%u\n",
                                   proto==6?"TCP":(proto==17?"UDP":"IP"),
                                   src, sport, dst, dport, len);
                        }
                    } else {
                        printf("VLAN frame len=%u\n", len);
                    }

                    if (args.hexdump > 0) {
                        int dump = std::min((int)len, args.hexdump);
                        for (int o=0; o<dump; o++) {
                            if (o%16==0) printf("  %04x: ", o);
                            printf("%02x ", pkt[o]);
                            if (o%16==15 || o+1==dump) printf("\n");
                        }
                    }
                }
            }

            bool drop_this = args.drop;

            if (args.reinject_tun) {
                // --- Re-inject via TUN (expects L3 only) ---
                if (len >= 14) {
                    const uint8_t* l2 = pkt;
                    uint16_t proto = (l2[12] << 8) | l2[13];
                    const uint8_t* l3 = nullptr;

                    if (proto == 0x8100 /* 802.1Q */) {
                        if (len >= 18) {
                            proto = (l2[16] << 8) | l2[17];
                            l3 = pkt + 18;
                        }
                    } else {
                        l3 = pkt + 14;
                    }

                    if (!drop_this && l3 && proto == 0x0800 /* IPv4 */) {
                        size_t l3_len = (pkt + len) - l3;
                        // (Optional) sanity checks: verify ihl/tot_len inside IP header
                        ssize_t n = write(tun_fd, l3, l3_len);
                        if (n >= 0) {
                            tx_pkts++;
                            // recycle UMEM frame immediately (we consumed the data)
                            uint32_t fidx;
                            if (xsk_ring_prod__reserve(&fq, 1, &fidx) == 1) {
                                *xsk_ring_prod__fill_addr(&fq, fidx) = addr;
                                xsk_ring_prod__submit(&fq, 1);
                            }
                        } else {
                            // TUN backpressure: recycle for RX and count as drop
                            uint32_t fidx;
                            if (xsk_ring_prod__reserve(&fq, 1, &fidx) == 1) {
                                *xsk_ring_prod__fill_addr(&fq, fidx) = addr;
                                xsk_ring_prod__submit(&fq, 1);
                            }
                            drops++;
                        }
                        continue; // handled
                    }
                }
                // Non-IPv4 or parse fail → drop + recycle
                uint32_t fidx;
                if (xsk_ring_prod__reserve(&fq, 1, &fidx) == 1) {
                    *xsk_ring_prod__fill_addr(&fq, fidx) = addr;
                    xsk_ring_prod__submit(&fq, 1);
                }
                drops++;
                continue;
            }

            // --- Original L2 forward via AF_XDP TX (only if not using TUN) ---
            if (!drop_this && reserved_tx) {
                struct xdp_desc* txd = xsk_ring_prod__tx_desc(&tx, idx_tx++);
                txd->addr = addr;
                txd->len  = len;
                tx_pkts++;
            } else {
                // Drop: recycle frame to FILL
                uint32_t fidx;
                if (xsk_ring_prod__reserve(&fq, 1, &fidx) == 1) {
                    *xsk_ring_prod__fill_addr(&fq, fidx) = addr;
                    xsk_ring_prod__submit(&fq, 1);
                }
                drops++;
            }
        }

        xsk_ring_cons__release(&rx, rcvd);

        if (!args.reinject_tun) {
            if (reserved_tx) {
                xsk_ring_prod__submit(&tx, reserved_tx);
                sendto(xsk_socket__fd(xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0);

                // Reap TX completions → recycle UMEM frames
                uint32_t idx_c;
                uint32_t done = xsk_ring_cons__peek(&cq, NUM_FRAMES, &idx_c);
                if (done) {
                    uint32_t fidx;
                    if (xsk_ring_prod__reserve(&fq, done, &fidx) == (int)done) {
                        for (uint32_t i=0; i<done; i++)
                            *xsk_ring_prod__fill_addr(&fq, fidx+i) =
                                *xsk_ring_cons__comp_addr(&cq, idx_c+i);
                        xsk_ring_prod__submit(&fq, done);
                        xsk_ring_cons__release(&cq, done);
                    }
                }
            }
        }

        if (args.verbose) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last).count() >= 1) {
                fprintf(stderr, "[v] stats: rx=%llu tx=%llu drop=%llu\n",
                        (unsigned long long)rx_pkts, (unsigned long long)tx_pkts, (unsigned long long)drops);
                last = now;
            }
        }
        fflush(stdout);
    }
    return 0;
}
