# AF_XDP Startup Path

This is the file-by-file path for running the eBPF/AF_XDP backend.

1. `CMakeLists.txt`
   Builds the core library, includes `XdpReader.cpp` and `XdpRuleController.cpp` when `OPENPENNY_WITH_XDP` is enabled, and exposes the `xdp_bpf` target for `ebpf/af_xdp/xdp_redirect_openpenny.o`.

2. `examples/configs/config_default.yaml`
   Includes `platform/af_xdp.yaml` for backend/interface/queue/ring settings and `policies/traffic_default.yaml` for traffic selection intent.

3. `src/config/Config.cpp`
   Resolves config includes, parses traffic/runtime/platform policy, compiles desired config, and adapts it into `Config::input`, `Config::xdp_runtime`, and `Config::traffic_match`.

4. `src/app/cli/cli_helpers.cpp`
   Parses startup flags such as `--source`, `--iface`, and queue options. Packet selection comes from compiled traffic policy.

5. `src/app/cli/source_setup.cpp`
   Applies CLI source selection. For XDP it sets `PacketInputBackend::XdpAfXdp` and enables XDP runtime attachment without rewriting traffic-match rules.

6. `src/app/cli/penny_cli.cpp`
   Loads config, ensures the BPF object exists, applies CLI overrides, builds `PipelineOptions`, and starts `drive_pipeline_threaded`.

7. `src/app/core/OpenpennyPipelineDriver.cpp`
   Copies the effective match config into pipeline options, creates one worker per queue, and requests a backend-neutral dataplane session from `dataplane::DefaultFactory`.

8. `src/dataplane/Factory.cpp`
   Dispatches on `Config::input.backend`: `XdpAfXdp` -> `XdpReader`, `AfPacketMirror` -> `AfPacketMirrorReader`, `Dpdk` -> `DpdkReader`. The driver rewrites `backend` before calling the factory when `input.mode` (auto/copy/redirect) mismatches the selected backend; see `OpenpennyPipelineDriver.cpp` for the resolution rules.

9. `src/net/PacketSourceFactory.cpp`
   Thin wrapper over the dataplane factory used by callers that want a
   `net::PacketSource` directly.

10. `src/ingress/af_xdp/XdpReader.cpp`
   Loads/attaches the BPF program, opens/pins maps, asks `XdpRuleController` to program match rules, creates UMEM and AF_XDP socket state, writes the socket fd into `xsks_map`, then polls packets. Runtime rule updates enter through `PacketSource::update_match_rules`.

11. `src/ingress/af_xdp/XdpRuleController.cpp`
    Encodes backend-neutral `TrafficMatchConfig` into BPF map structs and writes the rule array plus runtime settings map.

12. `ebpf/af_xdp/xdp_redirect_openpenny.c`
    Runs in the kernel at XDP hook time. It parses Ethernet/VLAN/IPv4/TCP/UDP, applies the configured rules from `conf` and `settings`, and redirects selected packets into `xsks_map`.

13. `src/net/PacketParser.cpp`
    Decodes AF_XDP frames into `PacketView`, including flow tuple, protocol, ports, TCP flags, payload length, and Layer 3 pointer.

14. `src/app/core/active/ActiveTestPipeline.cpp` or `src/app/core/passive/PassiveTestPipeline.cpp`
    Receives decoded packets from `PacketSource`, applies the shared traffic matcher at the flow level, then runs the active or passive Penny flow logic.

## Copy-mode shortcut (passive by default)

Passive mode takes a much shorter path. Steps 10-12 above do not run because no XDP program is loaded and no BPF maps are touched. Instead:

1. The driver resolves `input.mode = auto` to `copy` for passive mode and rewrites `input.backend` to `AfPacketMirror` if it was left at the default `af_xdp`.
2. `src/dataplane/Factory.cpp` dispatches to `AfPacketMirrorReader`.
3. `src/ingress/af_packet/AfPacketMirrorReader.cpp` opens a `SOCK_RAW` packet socket on the interface (`AF_PACKET`, `htons(ETH_P_ALL)`), binds it via `sockaddr_ll` to the resolved ifindex, and starts `recvfrom()`-based polling.
4. The kernel continues to deliver each packet up the normal stack to the final application; OpenPenny receives an observation-only copy alongside it.
5. `TrafficMatchConfig` is applied in userspace inside `AfPacketMirrorReader::poll()` before the packet is handed to the parser and pipeline.

No reinject round-trip is involved, so `cfg.egress.kind` can stay at `none`. The AF_PACKET backend has no libbpf or DPDK dependency and is always compiled in.
