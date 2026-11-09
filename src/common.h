#ifndef __PSFP_COMMON_H__
#define __PSFP_COMMON_H__

#include <linux/types.h>

/* Ethernet & TSN Protocol Identifiers */
#define ETH_P_8021Q        0x8100  /* IEEE 802.1Q VLAN Tag Protocol Identifier (TPID) */
#define ETH_P_OPCUA        0xB62C  /* OPC UA PubSub Raw Ethernet EtherType */
#define ETH_P_EXPERIMENTAL 0x88B5  /* IEEE 802 Local Experimental EtherType (Rogue / Noise) */

/* IEEE 802.1Qci PSFP Stream Rule & Real-time Traffic Counters */
struct stream_rule {
    __u32 gate_open;         /* Stream Gate: 1 = OPEN (Pass), 0 = CLOSED (Drop) */
    __u32 max_sdu_size;      /* Max Allowable SDU/Frame Size in Bytes (0 = unlimited) */
    __u64 rx_packets;        /* Accepted packets counter */
    __u64 rx_bytes;          /* Accepted bytes counter */
    __u64 dropped_packets;   /* Dropped packets counter (Gate CLOSED or SDU exceeded) */
};

/* IEEE 802.1Q Tagged Ethernet Header format */
struct vlan_hdr {
    __be16 h_vlan_TCI;                  /* Priority Code Point (3b), DEI (1b), VLAN ID (12b) */
    __be16 h_vlan_encapsulated_proto;   /* Inner encapsulated EtherType (e.g. 0xB62C) */
};

#endif /* __PSFP_COMMON_H__ */
