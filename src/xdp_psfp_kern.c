#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/*
 * IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP) in XDP
 *
 * Stream Identification:
 *   - Tagged frames: Stream ID is mapped from VLAN ID (VID in TCI).
 *   - Untagged OPC UA (0xB62C): Mapped to Stream 100.
 *   - Untagged background traffic: Stream 0 (Default pass).
 *
 * Stream Gate & SDU Filter:
 *   - gate_open == 1: Frame permitted to pass.
 *   - gate_open == 0: Stream gate closed, drop frame.
 *   - max_sdu_size > 0 && pkt_len > max_sdu_size: Drop frame exceeding SDU limit.
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct stream_rule);
    __uint(max_entries, 64);
} stream_map SEC(".maps");

/* Self-initialize default PSFP stream rules if not yet populated */
static __always_inline void init_default_rules(void)
{
    __u32 key_opcua = 100;
    struct stream_rule *rule_opcua = bpf_map_lookup_elem(&stream_map, &key_opcua);
    if (!rule_opcua) {
        struct stream_rule r = {
            .gate_open = 1,        /* Gate OPEN: Allow OPC UA TSN stream */
            .max_sdu_size = 512,   /* Max allowable SDU size 512 bytes */
            .rx_packets = 0,
            .rx_bytes = 0,
            .dropped_packets = 0,
        };
        bpf_map_update_elem(&stream_map, &key_opcua, &r, BPF_ANY);
    }

    __u32 key_rogue = 200;
    struct stream_rule *rule_rogue = bpf_map_lookup_elem(&stream_map, &key_rogue);
    if (!rule_rogue) {
        struct stream_rule r = {
            .gate_open = 0,        /* Gate CLOSED: Drop rogue / unauthorized stream */
            .max_sdu_size = 0,
            .rx_packets = 0,
            .rx_bytes = 0,
            .dropped_packets = 0,
        };
        bpf_map_update_elem(&stream_map, &key_rogue, &r, BPF_ANY);
    }
}

SEC("xdp")
int xdp_psfp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 pkt_len = data_end - data;

    /* Initialize default PSFP policies on first packet */
    init_default_rules();

    /* 1. Parse Layer 2 Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u32 stream_id = 0;
    __u16 inner_proto = h_proto;

    void *cursor = (void *)(eth + 1);

    /* 2. IEEE 802.1Q Stream Identification */
    if (h_proto == ETH_P_8021Q) {
        struct vlan_hdr *vlh = cursor;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;

        __u16 tci = bpf_ntohs(vlh->h_vlan_TCI);
        stream_id = tci & 0x0FFF; /* 12-bit VLAN Identifier */
        inner_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
    } else if (h_proto == ETH_P_OPCUA) {
        /* Untagged OPC UA directly on raw Ethernet */
        stream_id = 100;
    }

    /* 3. Lookup PSFP Policy & Metering Table */
    struct stream_rule *rule = bpf_map_lookup_elem(&stream_map, &stream_id);
    if (!rule) {
        /* Unregistered tagged streams are dropped; untagged background traffic passes */
        if (stream_id == 0)
            return XDP_PASS;

        bpf_printk("[PSFP] Stream %d: Unknown/Unregistered -> DROP (len %llu)\n", stream_id, pkt_len);
        return XDP_DROP;
    }

    /* 4. PSFP Stream Gate Evaluation (IEEE 802.1Qci Section 8.6.5.1) */
    if (rule->gate_open == 0) {
        rule->dropped_packets++;
        bpf_printk("[PSFP] Stream %d: Gate CLOSED -> DROP (len %llu)\n", stream_id, pkt_len);
        return XDP_DROP;
    }

    /* 5. PSFP Maximum SDU Size Filter (SDU Policing) */
    if (rule->max_sdu_size > 0 && pkt_len > rule->max_sdu_size) {
        rule->dropped_packets++;
        bpf_printk("[PSFP] Stream %d: SDU Exceeded (%llu > %u) -> DROP\n", stream_id, pkt_len, rule->max_sdu_size);
        return XDP_DROP;
    }

    /* 6. Stream Accounting & Metering */
    rule->rx_packets++;
    rule->rx_bytes += pkt_len;
    bpf_printk("[PSFP] Stream %d: PASS (proto 0x%04x, len %llu)\n", stream_id, inner_proto, pkt_len);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
