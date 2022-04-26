#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") xdp_map = {
    .type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1000,
    .map_flags = 0
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 zero = 0;
    __u32 *value;
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
        value = bpf_map_lookup_elem(&xdp_map, &iph->saddr);
        if(!value){
            bpf_map_update_elem(&xdp_map, &iph->saddr, &zero, BPF_NOEXIST);
            value = bpf_map_lookup_elem(&xdp_map, &iph->saddr);
            if(!value) {
                return XDP_PASS;
            }
        }
        (*value)++;
        return XDP_DROP;
    }

    return XDP_PASS;
}