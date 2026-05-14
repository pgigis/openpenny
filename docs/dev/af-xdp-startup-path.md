# AF_XDP Startup Path

File-by-file walk of how the eBPF / AF_XDP backend brings itself up.

1. **`CMakeLists.txt`** — builds the core library, pulls in `XdpReader.cpp`
   and `XdpRuleController.cpp` when `OPENPENNY_WITH_XDP` is on, and exposes
   the `xdp_bpf` target for `ebpf/af_xdp/xdp_redirect_openpenny.o`.

2. **`examples/configs/config_default.yaml`** — includes
   `platform/af_xdp.yaml` (backend / interface / queue / ring settings)
   and `policies/traffic_default.yaml` (traffic selection intent).

3. **`src/config/Config.cpp`** — resolves includes, schema-validates, parses
   `traffic_policy` / `runtime_policy` / `platform` / `egress`, compiles
   desired into effective config, and writes the legacy `Config::input`,
   `Config::xdp_runtime`, `Config::traffic_match` fields via
   `apply_desired_config_to_legacy`.

4. **`src/app/cli/cli_helpers.cpp`** — parses startup flags (`--source`,
   `--iface`, queue options). Packet selection comes from the compiled
   traffic policy.

5. **`src/app/cli/source_setup.cpp`** — applies CLI source selection. For
   XDP it sets `PacketInputBackend::XdpAfXdp` and enables XDP runtime
   attachment without rewriting traffic-match rules.

6. **`src/app/cli/penny_cli.cpp`** — loads config, ensures the BPF object
   exists, applies CLI overrides, builds `PipelineOptions`, and starts
   `drive_pipeline_threaded`.

7. **`src/app/core/OpenpennyPipelineDriver.cpp`** — copies the effective
   match config into pipeline options, creates one worker per queue, and
   requests a backend-neutral dataplane session from
   `dataplane::DefaultFactory`.

8. **`src/dataplane/Factory.cpp`** — dispatches on `Config::input.backend`:
   `XdpAfXdp → XdpReader`, `AfPacketMirror → AfPacketMirrorReader`,
   `Dpdk → DpdkReader`. The driver rewrites `backend` before calling the
   factory when `input.mode` (auto / copy / redirect) mismatches the
   selected backend.

9. **`src/net/PacketSourceFactory.cpp`** — thin wrapper over the dataplane
   factory for callers that want a `net::PacketSource` directly.

10. **`src/ingress/af_xdp/XdpReader.cpp`** — loads and attaches the BPF
    program, opens and pins maps, asks `XdpRuleController` to program
    match rules, creates UMEM and AF_XDP socket state, writes the socket
    fd into `xsks_map`, then polls packets. Runtime rule updates enter
    through `PacketSource::update_match_rules`.

11. **`src/ingress/af_xdp/XdpRuleController.cpp`** — encodes the
    backend-neutral `TrafficMatchConfig` into BPF map structs and writes
    the rule array plus runtime settings map.

12. **`ebpf/af_xdp/xdp_redirect_openpenny.c`** — runs in the kernel at the
    XDP hook. Parses Ethernet / VLAN / IPv4 / TCP / UDP, applies rules
    from `conf` and `settings`, and redirects selected packets into
    `xsks_map`.

13. **`src/net/PacketParser.cpp`** — decodes AF_XDP frames into
    `PacketView` (flow tuple, protocol, ports, TCP flags, payload length,
    L3 pointer).

14. **`src/app/core/active/ActiveTestPipeline.cpp`** or
    **`src/app/core/passive/PassiveTestPipeline.cpp`** — receives decoded
    packets, applies the shared traffic matcher at the flow level, and
    runs the active or passive Penny logic.

## Copy-mode shortcut (passive by default)

Passive mode skips steps 10-12: no XDP program is loaded and no BPF maps
are touched.

1. The driver resolves `input.mode = auto` to `copy` for passive and
   rewrites `input.backend` to `AfPacketMirror` when it was left at the
   default `af_xdp`.
2. `src/dataplane/Factory.cpp` dispatches to `AfPacketMirrorReader`.
3. `src/ingress/af_packet/AfPacketMirrorReader.cpp` opens a `SOCK_RAW`
   packet socket on the interface (`AF_PACKET`, `htons(ETH_P_ALL)`),
   binds via `sockaddr_ll` to the resolved ifindex, and polls via
   `recvfrom()`.
4. The kernel keeps delivering each packet up the normal stack to the
   final application; OpenPenny receives an observation copy alongside.
5. `TrafficMatchConfig` is applied in userspace inside
   `AfPacketMirrorReader::poll()` before the packet reaches the parser.

No reinject round-trip is involved, so `cfg.egress.kind` can stay at
`none`. The AF_PACKET backend has no libbpf or DPDK dependency and is
always compiled in.
