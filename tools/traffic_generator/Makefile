# Makefile shortcuts for the traffic generator.
#
# All targets that need to send raw packets re-exec themselves under sudo
# via run.sh. Override any variable on the command line, e.g.
#
#   make spoof IFACE=ens5f1np1 DEST_IP=10.0.0.5 DEST_PORT=9000 SRC_IP=198.51.100.10
#
# or in your shell:
#
#   IFACE=ens5f0np0 DEST_IP=192.168.43.3 DEST_PORT=5201 SRC_IP=198.51.100.10 make spoof

SHELL := /bin/bash
HERE  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# --- Required parameters (override on the command line) ---
IFACE      ?=
DEST_IP    ?=
DEST_PORT  ?= 9000
SRC_IP     ?=
DST_MAC    ?= ff:ff:ff:ff:ff:ff

# --- Tunable defaults (forwarded to run.sh) ---
FLOWS      ?= 1
COUNT      ?= 20
PAYLOAD    ?= 64
PORT       ?= 9000
HOST       ?= 127.0.0.1

EXPORT_VARS := \
  DEFAULT_FLOWS=$(FLOWS) \
  DEFAULT_COUNT=$(COUNT) \
  DEFAULT_PAYLOAD=$(PAYLOAD)

.PHONY: help install server client doctor spoof spoof-l2 mixed clean

help:
	@echo "Common targets:"
	@echo "  make install                                   - create .venv, install scapy"
	@echo "  make server PORT=9000                          - run the listener on PORT"
	@echo "  make client HOST=127.0.0.1 PORT=9000           - run the simple client"
	@echo "  make doctor IFACE=... DEST_IP=... SRC_IP=...   - run preflight only"
	@echo "  make spoof IFACE=... DEST_IP=... DEST_PORT=... SRC_IP=..."
	@echo "      Routed mode (kernel decides next hop)."
	@echo "  make spoof-l2 IFACE=... DST_MAC=... DEST_IP=... DEST_PORT=... SRC_IP=..."
	@echo "      L2 mode (you set the destination MAC)."
	@echo "  make mixed IFACE=... IPERF_SERVER=... DEST_IP=... SRC_IP=..."
	@echo "      iperf3 + spoofed flows together."
	@echo
	@echo "Tuning vars: FLOWS=$(FLOWS) COUNT=$(COUNT) PAYLOAD=$(PAYLOAD)"

install:
	@$(HERE)run.sh install

server:
	@$(EXPORT_VARS) $(HERE)run.sh server $(PORT)

client:
	@$(EXPORT_VARS) $(HERE)run.sh client $(HOST) $(PORT)

# Required-arg guard.
define need
$(if $($1),,$(error $1 is required, e.g. make $@ $1=...))
endef

doctor:
	$(call need,IFACE)
	$(call need,DEST_IP)
	$(call need,SRC_IP)
	@$(EXPORT_VARS) $(HERE)run.sh doctor $(IFACE) $(DEST_IP) $(SRC_IP)

spoof:
	$(call need,IFACE)
	$(call need,DEST_IP)
	$(call need,SRC_IP)
	@$(EXPORT_VARS) $(HERE)run.sh spoof $(IFACE) $(DEST_IP) $(DEST_PORT) $(SRC_IP)

spoof-l2:
	$(call need,IFACE)
	$(call need,DEST_IP)
	$(call need,SRC_IP)
	@$(EXPORT_VARS) $(HERE)run.sh spoof-l2 $(IFACE) $(DST_MAC) $(DEST_IP) $(DEST_PORT) $(SRC_IP)

mixed:
	$(call need,IFACE)
	$(call need,IPERF_SERVER)
	$(call need,DEST_IP)
	$(call need,SRC_IP)
	@$(EXPORT_VARS) $(HERE)run.sh mixed $(IFACE) $(IPERF_SERVER) $(DEST_IP) $(SRC_IP)

clean:
	rm -rf $(HERE).venv $(HERE)__pycache__
