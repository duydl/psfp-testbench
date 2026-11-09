#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " [TSN Testbench] Initializing Virtual Ethernet Topology   "
echo "=========================================================="

# 1. Clean existing interfaces if present
echo "[+] Cleaning up previous interfaces..."
ip netns del ns-pub 2>/dev/null || true
ip link del veth-sub 2>/dev/null || true

# 2. Create network namespace for publisher
echo "[+] Creating network namespace 'ns-pub'..."
ip netns add ns-pub

# 3. Create veth pair (veth-pub <--> veth-sub)
echo "[+] Creating veth pair (veth-pub <--> veth-sub)..."
ip link add veth-pub type veth peer name veth-sub

# 4. Move veth-pub into ns-pub namespace
echo "[+] Moving veth-pub into ns-pub namespace..."
ip link set veth-pub netns ns-pub

# 5. Assign L2 MAC addresses
# veth-pub: 02:00:00:00:00:01 (OPC UA TSN Publisher)
# veth-sub: 02:00:00:00:00:02 (TSN Gateway / Ingress Filter / Subscriber)
echo "[+] Assigning deterministic MAC addresses..."
ip netns exec ns-pub ip link set dev veth-pub address 02:00:00:00:00:01
ip link set dev veth-sub address 02:00:00:00:00:02

# 6. Disable L4/L3 offloads to ensure raw Layer 2 / XDP frame fidelity
echo "[+] Tuning interface offloads for raw TSN frame fidelity..."
ip netns exec ns-pub ethtool -K veth-pub rx off tx off gso off gro off tso off 2>/dev/null || true
ethtool -K veth-sub rx off tx off gso off gro off tso off 2>/dev/null || true

# 7. Bring up links
echo "[+] Bringing links UP..."
ip netns exec ns-pub ip link set dev lo up
ip netns exec ns-pub ip link set dev veth-pub up
ip link set dev veth-sub up

echo "----------------------------------------------------------"
echo " Virtual Testbed Topology Configured Successfully:"
echo "   Publisher  : [ns-pub]  -> veth-pub (02:00:00:00:00:01)"
echo "   Subscriber : [default] -> veth-sub (02:00:00:00:00:02)"
echo "=========================================================="
