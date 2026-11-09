#!/usr/bin/env python3
"""
TSN & Raw Ethernet Packet Printer / Sniffer
Captures frames arriving on veth-sub (after XDP PSFP processing),
decodes IEEE 802.1Q VLAN headers, OPC UA PubSub UADP payloads,
and outputs formatted hex/ASCII dumps.
"""

import argparse
import socket
import struct
import datetime
import json
import sys

ETH_P_8021Q = 0x8100
ETH_P_OPCUA = 0xB62C

def format_mac(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)

def hex_dump(data: bytes, indent: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{indent}{i:04x}   {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)

def parse_and_print_frame(packet: bytes, packet_num: int):
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    pkt_len = len(packet)

    if pkt_len < 14:
        print(f"[-] Malformed runt frame ({pkt_len} bytes)")
        return

    dst_mac = format_mac(packet[0:6])
    src_mac = format_mac(packet[6:12])
    ethertype = struct.unpack("!H", packet[12:14])[0]
    cursor = 14

    vid = None
    pcp = None
    inner_proto = ethertype

    # IEEE 802.1Q Tag Parsing
    if ethertype == ETH_P_8021Q:
        if pkt_len < 18:
            print("[-] Incomplete 802.1Q header")
            return
        tci, inner_proto = struct.unpack("!HH", packet[14:18])
        pcp = (tci >> 13) & 0x07
        dei = (tci >> 12) & 0x01
        vid = tci & 0x0FFF
        cursor = 18

    payload = packet[cursor:]

    print("\n" + "=" * 80)
    print(f" [FRAME #{packet_num:03d} RECEIVED]  Time: {now_str}  Length: {pkt_len} bytes")
    print("=" * 80)
    print(f"  Layer 2 MACs : {src_mac}  -->  {dst_mac}")
    if vid is not None:
        print(f"  802.1Q Tag   : VLAN ID = {vid}  |  Priority (PCP) = {pcp}  |  DEI = {dei}")
        print(f"  EtherType    : 0x{inner_proto:04X} ", end="")
    else:
        print(f"  EtherType    : 0x{ethertype:04X} ", end="")

    if inner_proto == ETH_P_OPCUA:
        print("(OPC UA PubSub Raw Ethernet - IEEE 802.1Qci Permitted Stream)")
        print("-" * 80)
        # Decode UADP
        if len(payload) >= 17:
            flags, pub_id, writer_id, ts_ns, seq_num = struct.unpack("!BHHQI", payload[0:17])
            uadp_data = payload[17:]
            print("  [OPC UA PubSub UADP NetworkMessage]")
            print(f"    Version & Flags : 0x{flags:02X}")
            print(f"    PublisherId     : 0x{pub_id:04X} ({pub_id})")
            print(f"    DataSetWriterId : {writer_id}")
            print(f"    Sequence Number : {seq_num}")
            print(f"    Header Timestamp: {ts_ns} ns")
            try:
                parsed_json = json.loads(uadp_data.decode("utf-8"))
                print("  [Decoded Telemetry Payload]")
                print("   ", json.dumps(parsed_json, indent=4).replace("\n", "\n    "))
            except Exception:
                print(f"  [Raw String Payload]: {uadp_data.decode('utf-8', errors='replace')}")
    else:
        print("(Generic / Unclassified Ethernet Frame)")
        print("-" * 80)
        print(f"  [Raw Payload String]: {payload[:80].decode('utf-8', errors='replace')}...")

    print("-" * 80)
    print("  [Packet Hex Dump (Complete Frame)]")
    print(hex_dump(packet))
    print("=" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(description="TSN Packet Sniffer & Payload Printer")
    parser.add_argument("--interface", "-i", default="veth-sub", help="Interface to sniff (default: veth-sub)")
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of frames to capture (0 = infinite)")
    parser.add_argument("--timeout", "-t", type=float, default=None, help="Sniffing timeout in seconds")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((args.interface, 0))

    if args.timeout:
        sock.settimeout(args.timeout)

    print(f"[*] Listening on interface '{args.interface}' (Raw L2 promiscuous)...")
    print("[*] Waiting for incoming TSN / OPC UA frames...")

    count = 0
    try:
        while True:
            try:
                packet = sock.recv(65535)
                count += 1
                parse_and_print_frame(packet, count)
                if args.count > 0 and count >= args.count:
                    print(f"[*] Captured {count} packet(s). Done.")
                    break
            except socket.timeout:
                print(f"[*] Timeout reached ({args.timeout}s). Captured {count} packet(s).")
                break
    except KeyboardInterrupt:
        print(f"\n[*] Interrupted by user. Total captured: {count}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
