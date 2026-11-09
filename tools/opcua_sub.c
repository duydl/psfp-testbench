#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
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

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static void print_hex_dump(const uint8_t *data, size_t len) {
    printf("  [Packet Hex Dump (%zu bytes)]\n", len);
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx   ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                uint8_t b = data[i + j];
                printf("%c", (b >= 32 && b <= 126) ? b : '.');
            }
        }
        printf("|\n");
    }
}

int main(int argc, char *argv[]) {
    const char *iface = "veth-sub";
    int max_count = 0;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"count",     required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:c:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'c': max_count = atoi(optarg); break;
            default: fprintf(stderr, "Usage: %s [-i interface] [-c count]\n", argv[0]); return EXIT_FAILURE;
        }
    }

    signal(SIGINT, sigint_handler);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[-] socket(AF_PACKET, SOCK_RAW) failed");
        return EXIT_FAILURE;
    }

    /* Bind to specific interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[-] SIOCGIFINDEX failed");
        close(sock);
        return EXIT_FAILURE;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[-] bind failed");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("================================================================================\n");
    printf(" Native C TSN Packet Sniffer listening on '%s' (ifindex %d)\n", iface, ifr.ifr_ifindex);
    printf(" Waiting for frames passing XDP PSFP kernel filter...\n");
    printf("================================================================================\n\n");

    uint8_t buffer[65535];
    int pkt_num = 0;

    while (running) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (errno == EINTR) break;
            perror("[-] recvfrom failed");
            break;
        }

        if (len < 14) continue;

        pkt_num++;
        time_t now = time(NULL);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

        uint16_t ethertype = (buffer[12] << 8) | buffer[13];
        int cursor = 14;
        int has_vlan = 0;
        uint16_t vid = 0, pcp = 0, dei = 0;
        uint16_t inner_proto = ethertype;

        if (ethertype == ETH_P_8021Q_VAL && len >= 18) {
            has_vlan = 1;
            uint16_t tci = (buffer[14] << 8) | buffer[15];
            pcp = (tci >> 13) & 0x07;
            dei = (tci >> 12) & 0x01;
            vid = tci & 0x0FFF;
            inner_proto = (buffer[16] << 8) | buffer[17];
            cursor = 18;
        }

        printf("================================================================================\n");
        printf(" [NATIVE C CAPTURE #%03d]  Time: %s  Length: %zd bytes\n", pkt_num, time_str, len);
        printf("================================================================================\n");
        printf("  L2 MACs    : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11],
               buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);

        if (has_vlan) {
            printf("  802.1Q Tag : VLAN ID = %u | Priority (PCP) = %u | DEI = %u\n", vid, pcp, dei);
            printf("  Inner Proto: 0x%04X ", inner_proto);
        } else {
            printf("  EtherType  : 0x%04X ", ethertype);
        }

        if (inner_proto == ETH_P_OPCUA_VAL) {
            printf("(OPC UA PubSub Ethernet - IEEE 802.1Qci Permitted Stream)\n");
            printf("--------------------------------------------------------------------------------\n");
            if (len >= cursor + 17) {
                const uint8_t *uadp = buffer + cursor;
                uint8_t flags = uadp[0];
                uint16_t pub_id = (uadp[1] << 8) | uadp[2];
                uint16_t writer_id = (uadp[3] << 8) | uadp[4];
                uint32_t seq = (uadp[13] << 24) | (uadp[14] << 16) | (uadp[15] << 8) | uadp[16];

                printf("  [OPC UA PubSub UADP NetworkMessage]\n");
                printf("    Version & Flags : 0x%02X\n", flags);
                printf("    PublisherId     : 0x%04X (%u)\n", pub_id, pub_id);
                printf("    DataSetWriterId : %u\n", writer_id);
                printf("    Sequence Number : %u\n", seq);

                const char *payload_str = (const char *)(uadp + 17);
                int payload_len = len - cursor - 17;
                printf("  [Decoded Payload (%d bytes)]:\n", payload_len);
                printf("    %.*s\n", payload_len, payload_str);
            }
        } else {
            printf("(Generic / Raw Ethernet Frame)\n");
        }

        printf("--------------------------------------------------------------------------------\n");
        print_hex_dump(buffer, len);
        printf("================================================================================\n\n");

        if (max_count > 0 && pkt_num >= max_count) {
            printf("[*] Captured target %d packet(s). Exiting.\n", max_count);
            break;
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}
