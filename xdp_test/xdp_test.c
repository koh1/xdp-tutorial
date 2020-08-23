//
// Created by koh1 on 2020/08/18.
//
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ptrace.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


struct flow_key {
    __u32 sip;
    __u32 dip;
    __u32 spt;
    __u32 dpt;
};

union bpf_attr my_map = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
};
int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));


SEC("prog")
int xdp_prog_simple(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    __u16 eth_payload_proto = eth->h_proto;
    if (eth_payload_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    __u16 ip_payload_proto = iph->protocol;
    if (ip_payload_proto != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }
    if (tcph->ack == 1) {
        char fmt[] = "Hello\n";
        __be16 win = tcph->window;
        tcph->window = bpf_htons(9999);
        __sum16 sum = (tcph->check) + 9999 + ((~win & 0xffff) + 1);
        tcph->check = bpf_htons(sum & 0xffff);
        bpf_trace_printk(fmt, sizeof(fmt));
        return XDP_PASS;
    }
    return XDP_PASS;
}
char __license[] SEC("license") = "GPL";
