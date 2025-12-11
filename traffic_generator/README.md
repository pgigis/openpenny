# TCP Traffic Generator

Two simple Python scripts plus an optional spoofed sender help generate TCP traffic for lab testing:

- `server.py`: listens on a given host/port and prints any bytes received.
- `client.py`: connects to the server and sends a message every second.
- `spoofed_client.py`: crafts flows with Scapy and injects them at L2 (useful for controlled sequence numbers, duplicates, and multi-flow bursts).
- `mixed_traffic.py`: launches iperf3 client traffic alongside spoofed flows for mixed workloads.

## Usage

Start the server (listen on all interfaces, port 9000):

```bash
python3 server.py --host 0.0.0.0 --port 9000
```

Start the client in another terminal (connects to 127.0.0.1:9000 and sends a line every second):

```bash
python3 client.py --host 127.0.0.1 --port 9000 --message "hello openpenny"
```

Use `Ctrl+C` in either terminal to stop.

## Spoofed flows (Scapy)

Requirements: `pip install scapy`

Install dependencies in a virtualenv (optional):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # if you add one; otherwise pip install scapy
```

Generate 3 spoofed flows with 20 data packets each, broadcast MAC, no pacing:
```bash
sudo python3 spoofed_client.py \
  --iface ens5f0np0 \
  --dst-mac ff:ff:ff:ff:ff:ff \
  --dest-ip 192.0.2.10 --dest-port 9000 \
  --src-ip 198.51.100.10 \
  --flows 3 --count 20 --payload-size 64
```

Add duplication and pacing jitter:
```bash
sudo python3 spoofed_client.py \
  --iface ens5f0np0 \
  --dst-mac ff:ff:ff:ff:ff:ff \
  --dest-ip 192.0.2.10 --dest-port 9000 \
  --src-ip 198.51.100.10 \
  --flows 2 --count 10 --payload-size 48 \
  --interval 0.02 --interval-jitter 0.01 \
  --duplication-prob 0.1 \
  --debug
```

## Using with openpenny CLI (example)

Run the server to capture payloads:
```bash
python3 server.py --host 0.0.0.0 --port 9000
```

Run openpenny in active mode (adjust iface/queue/prefix):
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode active \
  --prefix 198.51.100.0 \
  --mask-bits 24 \
  --iface ens5f0np0 \
  --queue 0 \
  --tun xdp-tun
```

Generate spoofed traffic toward the server:
```bash
sudo python3 spoofed_client.py \
  --iface ens5f0np0 \
  --dst-mac ff:ff:ff:ff:ff:ff \
  --dest-ip 198.51.100.20 --dest-port 9000 \
  --src-ip 198.51.100.10 \
  --flows 2 --count 15 --payload-size 64
```

Watch openpenny logs for drops/duplicates/retransmissions and server output for received payloads. Adjust `--prefix/--mask-bits` to filter to your spoofed subnet.

## Mixed traffic (iperf + spoofed)

Run iperf3 client plus spoofed flows in parallel:
```bash
python3 mixed_traffic.py \
  --iperf-server 192.0.2.20 --iperf-port 5201 --iperf-parallel 4 --iperf-duration 30 \
  --iface ens5f0np0 --dst-mac ff:ff:ff:ff:ff:ff \
  --spoof-dest-ip 198.51.100.20 --spoof-dest-port 9000 \
  --spoof-src-ip 198.51.100.10 --spoof-flows 2 --spoof-count 15 --spoof-payload 64 \
  --spoof-interval 0.02 --spoof-jitter 0.01 --spoof-dup-prob 0.1
```

Requirements:
- iperf3 installed on the client host
- Scapy (`pip install -r traffic_generator/requirements.txt`)
