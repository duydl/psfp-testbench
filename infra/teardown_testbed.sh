#!/usr/bin/env bash
echo "=========================================================="
echo " [TSN Testbench] Tearing down Virtual Testbed             "
echo "=========================================================="

# Detach XDP program from veth-sub if attached
ip link set dev veth-sub xdp off 2>/dev/null || true
ip link set dev veth-sub xdpgeneric off 2>/dev/null || true

# Delete veth interface (deletes peer veth-pub automatically)
ip link del veth-sub 2>/dev/null || true

# Delete publisher namespace
ip netns del ns-pub 2>/dev/null || true

echo "[+] Teardown completed cleanly."
