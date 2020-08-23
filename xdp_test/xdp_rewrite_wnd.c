#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define SWAP_ORDER_16(X) ((((X)&0xff00 >> 8) | (((X)&0xff) << 8)))
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

struct flow_key {
    __u32 dip; __u32 sip; __u32 spt; __u32 dpt;
};

/*BPF_HASH(flow_table, struct flow_key, u64);*/

SEC("prog")
int xdp_rewrite_wnd(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    __u16 eth_payload_proto = eth->h_proto;
    if (eth_payload_proto != htons(ETH_P_IP)) {
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

    struct flow_key key;
    key.sip = iph->saddr;
    key.dip = iph->daddr;
    key.spt = tcph->source;
    key.dpt = tcph->dest;

    if (tcph->ack == 1) {
        __be16 win = tcph->window;
        tcph->window = htons(10);
        __sum16 sum = (tcph->check) + 10 + ((~win & 0xffff) + 1);
        tcph->check = htons(sum & 0xffff);
    }

    return XDP_PASS;
}

char __license[] SEC("lincense") = "GPL";