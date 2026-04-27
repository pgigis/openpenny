# Build standalone AF_XDP diagnostic helpers.
# These tools are not used by the OpenPenny runtime.

CXX ?= g++
CXXFLAGS = -O2 -g -std=gnu++17

# Use pkg-config to discover cflags/libs; fall back gracefully if needed.
LIBS_CFLAGS := $(shell pkg-config --cflags libbpf libxdp 2>/dev/null)
LIBS_LDFLAGS := $(shell pkg-config --libs libbpf libxdp 2>/dev/null)

ifeq ($(LIBS_CFLAGS),)
  LIBS_CFLAGS := -I/usr/include -I/usr/local/include
endif
ifeq ($(LIBS_LDFLAGS),)
  LIBS_LDFLAGS := -L/usr/lib64 -L/usr/local/lib64 -lbpf -lxdp -lelf
endif

all: xsk_print_forward

xsk_print_forward: xsk_print_forward.cpp
	$(CXX) $(CXXFLAGS) $(LIBS_CFLAGS) $< -o $@ $(LIBS_LDFLAGS) -lelf

clean:
	rm -f xsk_print_forward

.PHONY: all clean
