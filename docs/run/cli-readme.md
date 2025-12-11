# CLI Quick Reference

Binary: `./build/openpenny_cli`

## Build
```bash
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON   # or DPDK flags as needed
cmake --build build
```

## Active example
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode active \
  --prefix 192.168.41.0 \
  --mask-bits 24 \
  --iface <ifname> \
  --queue 0 \
  --tun xdp-tu
```

## Passive example
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode passive \
  --prefix 192.168.41.0 \
  --mask-bits 24 \
  --iface <ifname> \
  --queue 0 \
  --no-forward-to-tun
```

Key flags:
- `--config` YAML path (uses full `monitoring` block)
- `--mode active|passive`
- `--prefix` / `--mask-bits`
- `--iface` / `--queue`
- `--tun` or `--no-forward-to-tun`; `--forward-raw-socket` + `--forward-device` for raw forwarding
- `--log-level debug` for verbose logging

More detail: `docs/run/cli-guide.md` and `docs/dev/active-passive-overview.md`.
