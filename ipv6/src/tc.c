#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") inet4_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1000,
    .map_flags = 0};
struct bpf_map_def SEC("maps") inet6_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(__u64),
    .max_entries = 1000,
    .map_flags = 0};

SEC("tc_prog")
int tc(struct __sk_buff *skb)
{

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u64 *value;
    __u64 zero = 0;
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = data + nh_off;
        if ((void *)&iph[1] > data_end)
            return TC_ACT_OK;

        value = bpf_map_lookup_elem(&inet4_map, &iph->daddr);
        if (!value)
        {
            bpf_map_update_elem(&inet4_map, &iph->daddr, &zero, BPF_NOEXIST);
            value = bpf_map_lookup_elem(&inet4_map, &iph->daddr);
            if (!value)
            {
                return TC_ACT_OK;
            }
        }
        (*value) += bpf_ntohs(iph->tot_len); 
        return TC_ACT_OK;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = data + nh_off;
        if((void *)&ip6h[1] > data_end)
            return TC_ACT_OK;

        value = bpf_map_lookup_elem(&inet6_map, &ip6h->daddr.in6_u);
        if (!value)
        {
            bpf_map_update_elem(&inet6_map, &ip6h->daddr.in6_u, &zero, BPF_NOEXIST);
            value = bpf_map_lookup_elem(&inet6_map, &ip6h->daddr.in6_u);
            if (!value)
            {
                return TC_ACT_OK;
            }
        }

        (*value) += bpf_ntohs(ip6h->payload_len);       
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}