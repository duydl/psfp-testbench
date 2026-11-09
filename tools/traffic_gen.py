#!/usr/bin/env python3
"""
TSN & Raw Ethernet Traffic Generator
Crafts IEEE 802.1Q tagged frames with OPC UA PubSub (EtherType 0xB62C),
rogue stream payloads, oversized SDU frames, and random noise.
"""

import argparse
import socket
import struct
import time
import json
import random

ETH_P_8021Q = 0x8100
ETH_P_OPCUA = 0xB62C
ETH_P_EXPERIMENTAL = 0x88B5

DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"

def mac_str_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))

def craft_ethernet_header(dst_mac: str, src_mac: str, ethertype: int) -> bytes:
    return mac_str_to_bytes(dst_mac) + mac_str_to_bytes(src_mac) + struct.pack("!H", ethertype)

def craft_vlan_tag(pcp: int, dei: int, vid: int, encapsulated_proto: int) -> bytes:
    tci = ((pcp & 0x07) << 13) | ((dei & 0x01) << 12) | (vid & 0x0FFF)
    return struct.pack("!HH", tci, encapsulated_proto)

def craft_opcua_uadp_payload(pub_id: int, writer_id: int, seq_num: int, data_dict: dict) -> bytes:
    """
    OPC UA Part 14 UADP NetworkMessage layout:
      - Byte 0: Flags (0x71: Version 1, PublisherId present, DataSetMessage present)
      - Bytes 1..2: PublisherId (uint16)
      - Bytes 3..4: DataSetWriterId (uint16)
      - Bytes 5..8: SequenceNumber (uint32)
      - Bytes 9..16: Timestamp (uint64 nanoseconds)
      - Bytes 17..: Payload (UTF-8 JSON string)
    """
    flags = 0x71
    ts_ns = int(time.time() * 1e9)
    payload_bytes = json.dumps(data_dict, separators=(',', ':')).encode("utf-8")
    header = struct.pack("!BHHQI", flags, pub_id, writer_id, ts_ns, seq_num)
    return header + payload_bytes

def main():
    parser = argparse.ArgumentParser(description="TSN & Raw Ethernet Traffic Generator for PSFP Testbench")
    parser.add_argument("--interface", "-i", default="veth-pub", help="Egress interface (default: veth-pub)")
    parser.add_argument("--stream", "-s", choices=["opcua", "rogue", "oversized", "random"], default="opcua",
                        help="Stream profile to generate")
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC, help=f"Source MAC (default: {DEFAULT_SRC_MAC})")
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC, help=f"Destination MAC (default: {DEFAULT_DST_MAC})")
    parser.add_argument("--count", "-c", type=int, default=1, help="Number of frames to transmit (default: 1)")
    parser.add_argument("--interval", type=float, default=0.2, help="Interval between frames in seconds")
    parser.add_argument("--vid", type=int, default=None, help="Override VLAN ID")
    parser.add_argument("--pcp", type=int, default=None, help="Override 802.1Q Priority Code Point (0-7)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.interface, 0))

    print(f"[*] Opening raw socket on {args.interface}...")
    print(f"[*] Sending {args.count} frame(s) of profile '{args.stream}'...")

    for i in range(1, args.count + 1):
        if args.stream == "opcua":
            # Authorized Stream 100: OPC UA PubSub over TSN (VLAN 100, PCP 6)
            vid = args.vid if args.vid is not None else 100
            pcp = args.pcp if args.pcp is not None else 6
            telemetry = {
                "station": "TSN_PUMP_STATION_ALPHA",
                "pressure_bar": round(4.5 + random.uniform(-0.2, 0.2), 3),
                "motor_temp_c": round(68.2 + random.uniform(-0.5, 0.8), 2),
                "vibration_g": round(0.045 + random.uniform(-0.005, 0.01), 4),
                "status": "OPERATIONAL_STABLE"
            }
            uadp = craft_opcua_uadp_payload(pub_id=0x1001, writer_id=1, seq_num=i, data_dict=telemetry)
            eth = craft_ethernet_header(args.dst_mac, args.src_mac, ETH_P_8021Q)
            vlan = craft_vlan_tag(pcp=pcp, dei=0, vid=vid, encapsulated_proto=ETH_P_OPCUA)
            packet = eth + vlan + uadp

        elif args.stream == "rogue":
            # Unauthorized Stream 200: Rogue payload (VLAN 200, PCP 1) -> Dropped by PSFP
            vid = args.vid if args.vid is not None else 200
            pcp = args.pcp if args.pcp is not None else 1
            payload = f"[ATTACK_VECTOR_PAYLOAD: ROGUE_STREAM_INJECTION_SEQ_{i}]".encode("utf-8")
            eth = craft_ethernet_header(args.dst_mac, args.src_mac, ETH_P_8021Q)
            vlan = craft_vlan_tag(pcp=pcp, dei=0, vid=vid, encapsulated_proto=ETH_P_EXPERIMENTAL)
            packet = eth + vlan + payload

        elif args.stream == "oversized":
            # Stream 100, but payload exceeds max_sdu_size (512 bytes) -> Dropped by PSFP SDU policing
            vid = args.vid if args.vid is not None else 100
            pcp = args.pcp if args.pcp is not None else 6
            oversized_padding = b"X" * 650
            payload = b"[OVERSIZED_JABBERING_FRAME_VIOLATION]" + oversized_padding
            eth = craft_ethernet_header(args.dst_mac, args.src_mac, ETH_P_8021Q)
            vlan = craft_vlan_tag(pcp=pcp, dei=0, vid=vid, encapsulated_proto=ETH_P_OPCUA)
            packet = eth + vlan + payload

        elif args.stream == "random":
            # Untagged random Ethernet frame
            random_payload = bytes([random.randint(0, 255) for _ in range(64)])
            eth = craft_ethernet_header(args.dst_mac, args.src_mac, ETH_P_EXPERIMENTAL)
            packet = eth + random_payload

        sock.send(packet)
        print(f"[>] Frame #{i} transmitted: {len(packet)} bytes (Profile: {args.stream}, VID: {vid if 'vid' in locals() else 'None'})")

        if i < args.count:
            time.sleep(args.interval)

    sock.close()
    print("[*] Transmission complete.")

if __name__ == "__main__":
    main()
