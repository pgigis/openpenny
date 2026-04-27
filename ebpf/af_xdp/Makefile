# Build the OpenPenny XDP program loaded by the AF_XDP runtime.
# Standalone diagnostic AF_XDP tools live under ../../tools/af_xdp.
# Requires: clang and Linux eBPF headers.

IFXDP ?=

BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

all: xdp_redirect_openpenny.o

xdp_redirect_openpenny.o: xdp_redirect_openpenny.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f xdp_redirect_openpenny.o

# Helper: manual attach via bpftool (native).
# Usage: make -C ebpf/af_xdp attach IFXDP=<interface>
attach: xdp_redirect_openpenny.o
	@test -n "$(IFXDP)" || { echo "IFXDP is required. Example: make -C ebpf/af_xdp attach IFXDP=eth0"; exit 2; }
	sudo ip link set dev $(IFXDP) xdp off || true
	sudo bpftool prog load ./xdp_redirect_openpenny.o /sys/fs/bpf/xdp_fw_prog type xdp pinmaps /sys/fs/bpf
	sudo bpftool net attach xdp pinned /sys/fs/bpf/xdp_fw_prog dev $(IFXDP)

status:
	@test -n "$(IFXDP)" || { echo "IFXDP is required. Example: make -C ebpf/af_xdp status IFXDP=eth0"; exit 2; }
	ip -d link show dev $(IFXDP) | sed -n '/xdp/,+6p'

.PHONY: all clean attach status
