# IEEE 802.1Qci (PSFP) eBPF/XDP Testbench for TSN & OPC UA PubSub

This repository implements a standalone, end-to-end experimental testbed for **IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP)** using Linux kernel **eBPF (Extended Berkeley Packet Filter)** in the **XDP (eXpress Data Path)** driver/generic layer.

It was designed to evaluate deterministic packet ingress gating and policing for **OPC UA PubSub over Raw Ethernet (EtherType 0xB62C)** on high-speed TSN hardware interfaces (such as NVIDIA Mellanox ConnectX-6 Dx).

---

## 1. IEEE 802.1Qci PSFP Architecture

IEEE 802.1Qci defines ingress policing mechanisms to prevent network disruption caused by faulty, misconfigured, or malicious endpoints (e.g. babbling idiot attacks or unauthorized streams):

```
+----------------------------------------------------------------------------------------------------+
|                                    NIC RX Ring / Ingress Port                                      |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
                        +───────────────────────────────────────────────────+
                        | 1. Stream Identification Function                 |
                        |    - Extracts 802.1Q VLAN ID (VID) & PCP          |
                        |    - Identifies OPC UA TSN Stream (e.g. Stream 100)|
                        +───────────────────────────────────────────────────+
                                                  │
                                                  ▼
                        +───────────────────────────────────────────────────+
                        | 2. Stream Filter & Gate Instance                  |
                        |    - Checks Stream Gate State (OPEN vs CLOSED)    |
                        |    - If CLOSED: Drop immediately (XDP_DROP)       |
                        +───────────────────────────────────────────────────+
                                                  │
                                                  ▼
                        +───────────────────────────────────────────────────+
                        | 3. Flow Meter & SDU Size Filter                   |
                        |    - Inspects frame length (pkt_len)              |
                        |    - Drops oversized/jabbering frames (SDU Limit) |
                        +───────────────────────────────────────────────────+
                                                  │
                                                  ▼
                     [ XDP_PASS: Forward frame to OS / Subscriber App ]
```

By executing this logic inside **XDP**, unwanted or malicious traffic is dropped directly at the NIC RX descriptor ring, completely bypassing `sk_buff` allocation, socket buffer queues, and kernel TCP/IP stack overhead.

---

## 2. Repository Structure

```
psfp-testbench/
├── infra/
│   ├── setup_testbed.sh      # Creates veth-pub <-> veth-sub & namespace ns-pub
│   └── teardown_testbed.sh   # Cleans up interfaces and namespaces
├── src/
│   ├── common.h              # Shared TSN & PSFP C struct definitions
│   ├── xdp_psfp_kern.c       # Kernel eBPF XDP program for stream filtering
│   └── Makefile              # Builds BPF bytecode (.o) with Clang
├── tools/
│   ├── traffic_gen.py        # Raw AF_PACKET generator (OPC UA PubSub & Rogue)
│   ├── packet_printer.py     # Real-time sniffer & payload/hex inspector
│   └── dump_metrics.py       # Dumps BPF stream_map counters & gate states
└── README.md
```

---

## 3. Quick Start & Execution

### Step 1: Compile the eBPF Program
```bash
cd src
make
# Generates xdp_psfp_kern.o
```

### Step 2: Initialize Virtual Testbed
```bash
sudo ./infra/setup_testbed.sh
```

### Step 3: Attach XDP Filter to Subscriber Interface
```bash
# Attach in generic mode (or driver mode on ConnectX-6 Dx: 'xdpdrv')
sudo ip link set dev veth-sub xdpgeneric obj src/xdp_psfp_kern.o sec xdp
```

### Step 4: Run the Packet Sniffer & Payload Printer
In one terminal window, listen on `veth-sub`:
```bash
sudo python3 tools/packet_printer.py -i veth-sub
```

### Step 5: Transmit Test Streams
In another terminal, transmit frames from the publisher namespace (`ns-pub`):

```bash
# 1. Transmit authorized OPC UA PubSub TSN stream (Stream 100, VLAN 100, PCP 6) -> DELIVERED
sudo ip netns exec ns-pub python3 tools/traffic_gen.py -i veth-pub --stream opcua --count 1

# 2. Transmit unauthorized rogue stream (Stream 200, VLAN 200) -> DROPPED by PSFP
sudo ip netns exec ns-pub python3 tools/traffic_gen.py -i veth-pub --stream rogue --count 1

# 3. Transmit oversized frame on Stream 100 (> 512 bytes SDU) -> DROPPED by SDU filter
sudo ip netns exec ns-pub python3 tools/traffic_gen.py -i veth-pub --stream oversized --count 1
```

### Step 6: Inspect PSFP Map Metrics
```bash
sudo python3 tools/dump_metrics.py
```

### Step 7: Teardown
```bash
sudo ./infra/teardown_testbed.sh
```
