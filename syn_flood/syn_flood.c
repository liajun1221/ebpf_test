#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syn_flood.skel.h"

static volatile bool exiting = false;

static void sig_int(int signo)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    const char *iface = "eth0"; // 默认网卡
    int ifindex;

    if (argc > 1)
        iface = argv[1];

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", iface);
        return 1;
    }

    struct syn_flood_bpf *skel;
    skel = syn_flood_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach XDP program to interface
    int prog_fd = bpf_program__fd(skel->progs.xdp_syn_flood_protect);
    int err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("SYN Flood protection active on %s. Press Ctrl+C to exit.\n", iface);

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching XDP program...\n");
    bpf_xdp_detach(ifindex, 0, NULL);

cleanup:
    syn_flood_bpf__destroy(skel);
    return 0;
}