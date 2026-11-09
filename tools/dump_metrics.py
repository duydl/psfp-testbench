#!/usr/bin/env python3
"""
PSFP BPF Map Metrics Inspector
Dumps stream_map using bpftool and renders the IEEE 802.1Qci stream statistics table.
"""

import subprocess
import json
import struct
import sys

def dump_map_with_bpftool():
    cmd = ["bpftool", "map", "dump", "name", "stream_map", "-p"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(proc.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[-] bpftool dump error: {e.stderr}")
        return None
    except FileNotFoundError:
        print("[-] bpftool command not found in PATH")
        return None

def parse_bytes(hex_list: list) -> bytes:
    return bytes(int(x, 16) for x in hex_list)

def print_table(entries):
    print("\n" + "=" * 90)
    print(" IEEE 802.1Qci Per-Stream Filtering & Policing (PSFP) Runtime Map Metrics")
    print("=" * 90)
    print(f" {'Stream ID':<12} | {'Gate State':<12} | {'Max SDU':<12} | {'RX Packets':<14} | {'RX Bytes':<14} | {'Dropped Packets':<16}")
    print("-" * 90)

    for stream_id, gate, sdu, rx_pkts, rx_bytes, dropped in entries:
        gate_str = "OPEN (Pass)" if gate == 1 else "CLOSED (Drop)"
        sdu_str = f"{sdu} B" if sdu > 0 else "Unlimited"
        desc = ""
        if stream_id == 100:
            desc = " (OPC UA TSN)"
        elif stream_id == 200:
            desc = " (Rogue Stream)"
        elif stream_id == 0:
            desc = " (Untagged)"

        print(f" {str(stream_id) + desc:<12} | {gate_str:<12} | {sdu_str:<12} | {rx_pkts:<14} | {rx_bytes:<14} | {dropped:<16}")

    print("=" * 90 + "\n")

def main():
    data = dump_map_with_bpftool()
    if not data:
        print("[!] No active stream_map found or insufficient privileges.")
        print("[!] Run with sudo: sudo python3 tools/dump_metrics.py")
        sys.exit(1)

    parsed_entries = []
    for item in data:
        # bpftool outputs formatted keys and values or hex arrays
        # Value struct: gate_open(u32), max_sdu_size(u32), rx_packets(u64), rx_bytes(u64), dropped_packets(u64)
        # Total size: 4 + 4 + 8 + 8 + 8 = 32 bytes
        if "key" in item and "value" in item:
            key_raw = item["key"]
            val_raw = item["value"]

            if isinstance(key_raw, list):
                stream_id = struct.unpack("<I", parse_bytes(key_raw))[0]
            elif isinstance(key_raw, int):
                stream_id = key_raw
            else:
                continue

            if isinstance(val_raw, list):
                val_bytes = parse_bytes(val_raw)
                if len(val_bytes) >= 32:
                    gate, sdu, rx_pkts, rx_bytes, dropped = struct.unpack("<IIQQQ", val_bytes[:32])
                    parsed_entries.append((stream_id, gate, sdu, rx_pkts, rx_bytes, dropped))
            elif isinstance(val_raw, dict):
                # BTF formatted JSON output
                gate = val_raw.get("gate_open", 0)
                sdu = val_raw.get("max_sdu_size", 0)
                rx_pkts = val_raw.get("rx_packets", 0)
                rx_bytes = val_raw.get("rx_bytes", 0)
                dropped = val_raw.get("dropped_packets", 0)
                parsed_entries.append((stream_id, gate, sdu, rx_pkts, rx_bytes, dropped))

    parsed_entries.sort(key=lambda x: x[0])
    print_table(parsed_entries)

if __name__ == "__main__":
    main()
