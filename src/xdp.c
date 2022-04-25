#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_PASS;

    if(eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
        return XDP_PASS;
    
    __u32 protocol = iph->protocol;
    if (protocol == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}