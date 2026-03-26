#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800  // IPv4
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD  // IPv6
#endif

#define RATE_LIMIT 100ULL          // 每秒最大 SYN 数
#define TIME_WINDOW (1000000000ULL) // 1 秒（纳秒）

struct syn_entry {
    __u64 last_time_ns;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         // IPv4 地址（网络序）
    __type(value, struct syn_entry);
} syn_track SEC(".maps");

__attribute__((always_inline, unused)) static bool is_syn_packet(struct tcphdr *tcp)
{
    return (tcp->syn == 1) && (tcp->ack == 0) && (tcp->rst == 0);
}

SEC("xdp")
int xdp_syn_flood_protect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((char*)ip + ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!is_syn_packet(tcp))
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct syn_entry *entry = bpf_map_lookup_elem(&syn_track, &src_ip);
    if (entry) {
        // 检查是否在时间窗口内
        if (now - entry->last_time_ns < TIME_WINDOW) {
            entry->count++;
            if (entry->count > RATE_LIMIT) {
                bpf_printk("ip: %d drop", src_ip);
                return XDP_DROP;
            }
        } else {
            // 超出窗口，重置计数
            entry->last_time_ns = now;
            entry->count = 1;
        }
        bpf_map_update_elem(&syn_track, &src_ip, entry, BPF_EXIST);
    } else {
        struct syn_entry new_entry = {
            .last_time_ns = now,
            .count = 1,
        };
        bpf_map_update_elem(&syn_track, &src_ip, &new_entry, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";