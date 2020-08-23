/* SPDX-License-Identifier: GPL-2.0 */


#define KBUILD_MODNAME "xdp_dummy"
#include <stddef.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf.h>

struct flow_key {
    __u32 sip;
    __u32 dip;
    __u32 spt;
    __u32 dpt;
};

int bpf_map = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct flow_key), sizeof(__u64), 256, 0);

SEC("prog")
int xdp_prog_simple(struct xdp_md *xdp) {
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

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
    if (ip_payload_proto == IPPROTO_ICMP) {
        char msg[] = "icmp protocol will be dropped\n";
        bpf_trace_printk(msg, sizeof(msg));
        char fmt3[] = "%u\n";
        bpf_trace_printk(fmt3, sizeof(fmt3), iph->saddr);
        bpf_trace_printk(fmt3, sizeof(fmt3), iph->daddr);
        return XDP_DROP;
    } else if (ip_payload_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
            return XDP_PASS;
        }
        if (tcph->ack == 1) {
            unsigned short win = tcph->window;
            char fmt[] = "window size: %u\n";
            bpf_trace_printk(fmt, sizeof(fmt), win);
            /*
            __be16 win = tcph->window;
            tcph->window = bpf_htons(1000);
            __sum16 sum = (tcph->check) + 1000 + ((~win & 0xffff) + 1);
            tcph->check = sum;
            char msg[] = "TCP ACK\n";
            bpf_trace_printk(msg, sizeof(msg));
            */
        }
    } else if (ip_payload_proto == IPPROTO_UDP) {
        char msg[] = "udp\n";
        bpf_trace_printk(msg, sizeof(msg));
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
