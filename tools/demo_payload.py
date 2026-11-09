#!/usr/bin/env python3
"""
Testbench Payload Demonstration:
Crafts and prints:
1. Stream 100: Authorized OPC UA PubSub Ethernet frame (802.1Q tagged, PCP 6, EtherType 0xB62C)
2. Stream 200: Rogue / Unauthorized stream payload (802.1Q tagged, PCP 1, EtherType 0x88B5)
3. Untagged random Ethernet noise payload
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from traffic_gen import (
    craft_ethernet_header,
    craft_vlan_tag,
    craft_opcua_uadp_payload,
    ETH_P_8021Q,
    ETH_P_OPCUA,
    ETH_P_EXPERIMENTAL,
)
from packet_printer import parse_and_print_frame

def main():
    print("=" * 80)
    print(" TSN TESTBENCH PAYLOAD DEMONSTRATION & VERIFICATION")
    print("=" * 80)

    # 1. Authorized OPC UA PubSub TSN Frame (Stream 100)
    print("\n[+] STREAM 1: AUTHORIZED OPC UA PUBSUB TSN FRAME (STREAM 100, VLAN 100, PCP 6)")
    telemetry = {
        "station": "TSN_PUMP_STATION_ALPHA",
        "pressure_bar": 4.512,
        "motor_temp_c": 68.45,
        "vibration_g": 0.0482,
        "status": "OPERATIONAL_OPTIMAL"
    }
    uadp = craft_opcua_uadp_payload(pub_id=0x1001, writer_id=1, seq_num=1042, data_dict=telemetry)
    eth = craft_ethernet_header("02:00:00:00:00:02", "02:00:00:00:00:01", ETH_P_8021Q)
    vlan = craft_vlan_tag(pcp=6, dei=0, vid=100, encapsulated_proto=ETH_P_OPCUA)
    pkt1 = eth + vlan + uadp
    parse_and_print_frame(pkt1, 1)

    # 2. Rogue Unauthorized Stream Frame (Stream 200)
    print("\n[+] STREAM 2: UNAUTHORIZED ROGUE STREAM FRAME (STREAM 200, VLAN 200, PCP 1)")
    payload_rogue = b"[ATTACK_VECTOR_PAYLOAD: ROGUE_STREAM_INJECTION_SEQ_99]"
    eth_rogue = craft_ethernet_header("02:00:00:00:00:02", "02:00:00:00:00:01", ETH_P_8021Q)
    vlan_rogue = craft_vlan_tag(pcp=1, dei=0, vid=200, encapsulated_proto=ETH_P_EXPERIMENTAL)
    pkt2 = eth_rogue + vlan_rogue + payload_rogue
    parse_and_print_frame(pkt2, 2)

    # 3. Untagged Random Ethernet Noise Payload
    print("\n[+] STREAM 3: UNTAGGED RANDOM ETHERNET NOISE PAYLOAD (48 BYTES)")
    random_payload = bytes(range(48))
    eth_rand = craft_ethernet_header("02:00:00:00:00:02", "02:00:00:00:00:01", ETH_P_EXPERIMENTAL)
    pkt3 = eth_rand + random_payload
    parse_and_print_frame(pkt3, 3)

if __name__ == "__main__":
    main()
