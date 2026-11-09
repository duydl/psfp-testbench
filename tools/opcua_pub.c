#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define ETH_P_8021Q_VAL     0x8100
#define ETH_P_OPCUA_VAL     0xB62C
#define ETH_P_EXP_VAL       0x88B5

/* 802.1Q VLAN Tag structure */
struct __attribute__((packed)) vlan_tag {
    uint16_t tpid;                 /* 0x8100 */
    uint16_t tci;                  /* PCP (3b), DEI (1b), VID (12b) */
    uint16_t encapsulated_proto;   /* e.g. 0xB62C */
};

/* OPC UA Part 14 UADP NetworkMessage Header */
struct __attribute__((packed)) uadp_hdr {
    uint8_t  flags;                /* 0x71: Ver 1, PubId present, DataSet present */
    uint16_t publisher_id;         /* Big-Endian */
    uint16_t dataset_writer_id;    /* Big-Endian */
    uint64_t timestamp_ns;         /* Big-Endian nanoseconds */
    uint32_t sequence_number;      /* Big-Endian */
};

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n"
                    "  -i, --interface <iface>   Network interface (default: veth-pub)\n"
                    "  -s, --stream <type>       opcua | rogue | oversized | noise (default: opcua)\n"
                    "  -c, --count <num>         Number of frames to send (default: 1)\n"
                    "  -d, --delay-ms <ms>       Delay between frames in ms (default: 100)\n"
                    "  -v, --vid <vid>           Override VLAN ID\n"
                    "  -p, --pcp <pcp>           Override 802.1Q Priority Code Point (0-7)\n", prog);
}

int main(int argc, char *argv[]) {
    const char *iface = "veth-pub";
    const char *stream_type = "opcua";
    int count = 1;
    int delay_ms = 100;
    int override_vid = -1;
    int override_pcp = -1;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"stream",    required_argument, 0, 's'},
        {"count",     required_argument, 0, 'c'},
        {"delay-ms",  required_argument, 0, 'd'},
        {"vid",       required_argument, 0, 'v'},
        {"pcp",       required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:s:c:d:v:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 's': stream_type = optarg; break;
            case 'c': count = atoi(optarg); break;
            case 'd': delay_ms = atoi(optarg); break;
            case 'v': override_vid = atoi(optarg); break;
            case 'p': override_pcp = atoi(optarg); break;
            default: print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    /* Open AF_PACKET raw socket */
    int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[-] socket(AF_PACKET, SOCK_RAW) failed");
        return EXIT_FAILURE;
    }

    /* Get interface index */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[-] SIOCGIFINDEX failed");
        close(sock);
        return EXIT_FAILURE;
    }
    int ifindex = ifr.ifr_ifindex;

    /* Set socket priority for TSN traffic */
    int priority = 6;
    if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0) {
        perror("[!] Warning: setsockopt(SO_PRIORITY) failed");
    }

    /* Setup sockaddr_ll */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = ETH_ALEN;
    /* Dst MAC: 02:00:00:00:00:02 */
    sll.sll_addr[0] = 0x02; sll.sll_addr[1] = 0x00; sll.sll_addr[2] = 0x00;
    sll.sll_addr[3] = 0x00; sll.sll_addr[4] = 0x00; sll.sll_addr[5] = 0x02;

    uint8_t buffer[1514];
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

    printf("[*] Native C TSN Generator active on interface '%s' (ifindex %d)\n", iface, ifindex);
    printf("[*] Profile: '%s' | Transmitting %d frame(s)...\n", stream_type, count);

    for (int seq = 1; seq <= count; seq++) {
        memset(buffer, 0, sizeof(buffer));
        int pkt_len = 0;

        /* Ethernet Header */
        memcpy(buffer, dst_mac, 6);
        memcpy(buffer + 6, src_mac, 6);

        if (strcmp(stream_type, "opcua") == 0) {
            /* Stream 100: Authorized OPC UA PubSub TSN Frame */
            uint16_t vid = (override_vid >= 0) ? override_vid : 100;
            uint16_t pcp = (override_pcp >= 0) ? override_pcp : 6;
            uint16_t tci = ((pcp & 0x07) << 13) | (vid & 0x0FFF);

            struct vlan_tag *vlan = (struct vlan_tag *)(buffer + 12);
            vlan->tpid = htons(ETH_P_8021Q_VAL);
            vlan->tci = htons(tci);
            vlan->encapsulated_proto = htons(ETH_P_OPCUA_VAL);

            /* OPC UA UADP Header */
            struct uadp_hdr *uadp = (struct uadp_hdr *)(buffer + 12 + sizeof(struct vlan_tag));
            uadp->flags = 0x71;
            uadp->publisher_id = htons(0x1001);
            uadp->dataset_writer_id = htons(1);
            uadp->sequence_number = htonl(seq);

            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
            uadp->timestamp_ns = htobe64(ts_ns);

            /* Telemetry JSON Payload */
            char telemetry[256];
            snprintf(telemetry, sizeof(telemetry),
                     "{\"device\":\"TSN_PUMP_01\",\"press_bar\":%.3f,\"temp_c\":%.2f,\"stat\":\"OPTIMAL\"}",
                     4.52 + (seq % 10) * 0.05, 68.4 + (seq % 5) * 0.2);

            int uadp_hdr_len = sizeof(struct uadp_hdr);
            int telem_len = strlen(telemetry);
            memcpy((uint8_t *)uadp + uadp_hdr_len, telemetry, telem_len);

            pkt_len = 12 + sizeof(struct vlan_tag) + uadp_hdr_len + telem_len;

        } else if (strcmp(stream_type, "rogue") == 0) {
            /* Stream 200: Rogue Unauthorized Stream */
            uint16_t vid = (override_vid >= 0) ? override_vid : 200;
            uint16_t pcp = (override_pcp >= 0) ? override_pcp : 1;
            uint16_t tci = ((pcp & 0x07) << 13) | (vid & 0x0FFF);

            struct vlan_tag *vlan = (struct vlan_tag *)(buffer + 12);
            vlan->tpid = htons(ETH_P_8021Q_VAL);
            vlan->tci = htons(tci);
            vlan->encapsulated_proto = htons(ETH_P_EXP_VAL);

            const char *attack = "[ROGUE_UNAUTHORIZED_STREAM_PAYLOAD_VIOLATION]";
            int attack_len = strlen(attack);
            memcpy(buffer + 12 + sizeof(struct vlan_tag), attack, attack_len);
            pkt_len = 12 + sizeof(struct vlan_tag) + attack_len;

        } else if (strcmp(stream_type, "oversized") == 0) {
            /* Stream 100 with SDU violation (> 512 bytes) */
            uint16_t vid = 100;
            uint16_t pcp = 6;
            uint16_t tci = ((pcp & 0x07) << 13) | (vid & 0x0FFF);

            struct vlan_tag *vlan = (struct vlan_tag *)(buffer + 12);
            vlan->tpid = htons(ETH_P_8021Q_VAL);
            vlan->tci = htons(tci);
            vlan->encapsulated_proto = htons(ETH_P_OPCUA_VAL);

            memset(buffer + 12 + sizeof(struct vlan_tag), 0xAA, 650);
            pkt_len = 12 + sizeof(struct vlan_tag) + 650;

        } else {
            /* Untagged noise */
            uint16_t proto = htons(ETH_P_EXP_VAL);
            memcpy(buffer + 12, &proto, 2);
            for (int j = 14; j < 64; j++) buffer[j] = (uint8_t)j;
            pkt_len = 64;
        }

        /* Send packet */
        ssize_t sent = sendto(sock, buffer, pkt_len, 0, (struct sockaddr *)&sll, sizeof(sll));
        if (sent < 0) {
            perror("[-] sendto failed");
        } else {
            printf("[>] Transmitted Frame #%d: %ld bytes (Profile: %s)\n", seq, sent, stream_type);
        }

        if (seq < count && delay_ms > 0) {
            usleep(delay_ms * 1000);
        }
    }

    close(sock);
    printf("[*] Native C transmission finished successfully.\n");
    return EXIT_SUCCESS;
}
