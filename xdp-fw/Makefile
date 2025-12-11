# Simple Makefile for XDP + AF_XDP userspace
# Requires: clang, g++, libbpf, libxdp, elfutils

IFXDP ?= ens5f0np0

BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

CXX ?= g++
CXXFLAGS = -O2 -g -std=gnu++17

# Use pkg-config to discover cflags/libs; fall back gracefully if needed
LIBS_CFLAGS := $(shell pkg-config --cflags libbpf libxdp 2>/dev/null)
LIBS_LDFLAGS := $(shell pkg-config --libs libbpf libxdp 2>/dev/null)

# If pkg-config didn't return anything, try common defaults
ifeq ($(LIBS_CFLAGS),)
  LIBS_CFLAGS := -I/usr/include -I/usr/local/include
endif
ifeq ($(LIBS_LDFLAGS),)
  LIBS_LDFLAGS := -L/usr/lib64 -L/usr/local/lib64 -lbpf -lxdp -lelf
endif

all: xdp_redirect_dstprefix.o xsk_print_forward

xdp_redirect_dstprefix.o: xdp_redirect_dstprefix.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

xsk_print_forward: xsk_print_forward.cpp
	$(CXX) $(CXXFLAGS) $(LIBS_CFLAGS) $< -o $@ $(LIBS_LDFLAGS) -lelf

clean:
	rm -f xdp_redirect_dstprefix.o xsk_print_forward

# Helper: manual attach via bpftool (native)
attach: xdp_redirect_dstprefix.o
	sudo ip link set dev $(IFXDP) xdp off || true
	sudo bpftool prog load ./xdp_redirect_dstprefix.o /sys/fs/bpf/xdp_fw_prog type xdp pinmaps /sys/fs/bpf
	sudo bpftool net attach xdp pinned /sys/fs/bpf/xdp_fw_prog dev $(IFXDP)

status:
	ip -d link show dev $(IFXDP) | sed -n '/xdp/,+6p'

.PHONY: all clean attach status
