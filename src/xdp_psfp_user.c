#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

static volatile int exiting = 0;

static void sigint_handler(int sig) {
    (void)sig;
    exiting = 1;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n"
                    "  -i, --interface <iface>   Target network interface (default: veth-sub)\n"
                    "  -o, --obj <path>          Path to BPF object (default: src/xdp_psfp_kern.o)\n", prog);
}

int main(int argc, char *argv[]) {
    const char *iface = "veth-sub";
    const char *obj_path = "src/xdp_psfp_kern.o";

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"obj",       required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'o': obj_path = optarg; break;
            default: print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "[-] Interface '%s' not found\n", iface);
        return EXIT_FAILURE;
    }

    printf("================================================================================\n");
    printf(" Native C / libbpf PSFP Manager & Loader\n");
    printf(" Interface: %s (ifindex %d) | BPF Object: %s\n", iface, ifindex, obj_path);
    printf("================================================================================\n");

    /* 1. Open BPF ELF Object */
    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[-] Failed to open BPF object '%s': %s\n", obj_path, strerror(errno));
        return EXIT_FAILURE;
    }

    /* 2. Load into Kernel (Verifier Execution) */
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[-] Verifier rejected BPF program: %d (%s)\n", err, strerror(-err));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] BPF object successfully verified and loaded into kernel.\n");

    /* 3. Find Program and Attach to XDP Hook */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_psfp_filter");
    if (!prog) {
        fprintf(stderr, "[-] Program 'xdp_psfp_filter' not found in object\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    int prog_fd = bpf_program__fd(prog);
    /* Attach using XDP_FLAGS_SKB_MODE (generic) for virtual veth pairs */
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err < 0) {
        fprintf(stderr, "[-] Failed to attach XDP to %s: %d (%s)\n", iface, err, strerror(-err));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Attached XDP PSFP filter to '%s' (prog_fd: %d).\n", iface, prog_fd);

    /* 4. Find Stream Map */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "stream_map");
    if (!map) {
        fprintf(stderr, "[-] Map 'stream_map' not found\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    int map_fd = bpf_map__fd(map);

    printf("[+] Monitoring IEEE 802.1Qci PSFP Stream Map (Press Ctrl+C to exit and detach)...\n\n");

    while (!exiting) {
        printf("\033[H\033[J"); /* Clear terminal */
        printf("=========================================================================================\n");
        printf(" IEEE 802.1Qci PSFP Real-Time Stream Table (Kernel Map FD %d)\n", map_fd);
        printf(" Interface: %s | Timestamp: %ld\n", iface, (long)time(NULL));
        printf("=========================================================================================\n");
        printf(" %-12s | %-12s | %-12s | %-14s | %-14s | %-16s\n",
               "Stream ID", "Gate State", "Max SDU (B)", "RX Packets", "RX Bytes", "Dropped Packets");
        printf("-----------------------------------------------------------------------------------------\n");

        uint32_t streams[] = {100, 200, 0};
        const char *descs[] = {"100 (OPC UA)", "200 (Rogue)", "0 (Untagged)"};

        for (int i = 0; i < 3; i++) {
            uint32_t key = streams[i];
            struct stream_rule rule;
            memset(&rule, 0, sizeof(rule));

            if (bpf_map_lookup_elem(map_fd, &key, &rule) == 0) {
                const char *gate_str = (rule.gate_open == 1) ? "OPEN (Pass)" : "CLOSED (Drop)";
                char sdu_str[32];
                if (rule.max_sdu_size > 0)
                    snprintf(sdu_str, sizeof(sdu_str), "%u B", rule.max_sdu_size);
                else
                    snprintf(sdu_str, sizeof(sdu_str), "Unlimited");

                printf(" %-12s | %-12s | %-12s | %-14llu | %-14llu | %-16llu\n",
                       descs[i], gate_str, sdu_str,
                       (unsigned long long)rule.rx_packets,
                       (unsigned long long)rule.rx_bytes,
                       (unsigned long long)rule.dropped_packets);
            }
        }
        printf("=========================================================================================\n");
        printf(" [Live Native libbpf C Monitor] Press Ctrl+C to detach XDP and clean up...\n");
        sleep(1);
    }

    printf("\n[+] Detaching XDP from '%s'...\n", iface);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("[+] Clean shutdown complete.\n");

    return EXIT_SUCCESS;
}
