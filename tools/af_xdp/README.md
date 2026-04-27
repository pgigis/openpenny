# AF_XDP Diagnostic Tools

This directory contains standalone AF_XDP helpers for local lab testing and
debugging. They are not part of the OpenPenny runtime path.

Files:

- `xsk_print_forward.cpp` - standalone AF_XDP socket app for receiving packets
  redirected by `xdp_redirect_openpenny.o`, printing summaries, and optionally
  TXing frames back out or reinjecting IPv4 into a TUN device.
- `cleanxdp.sh` and `disable_xdp.sh` - manual cleanup helpers for test hosts.
- `Makefile` - builds only the diagnostic helper.

The eBPF object used by OpenPenny remains in `../../ebpf/af_xdp/`.

## Build

```bash
make -C ebpf/af_xdp xdp_redirect_openpenny.o
make -C tools/af_xdp
```

The helper looks for the BPF object at:

- `xdp_redirect_openpenny.o`
- `ebpf/af_xdp/xdp_redirect_openpenny.o`
- `../../ebpf/af_xdp/xdp_redirect_openpenny.o`

## Example

```bash
sudo ./tools/af_xdp/xsk_print_forward \
  --if ens5f1np1 \
  --queue 0 \
  --prefix 192.168.41.0 \
  --mask 24 \
  --hexdump 64 \
  --verbose
```

The helper programs one source-prefix redirect rule into the current
`conf`/`settings` map layout. For production OpenPenny runs, use the CLI or
daemon instead; they program the full generic 5-tuple rule set.
