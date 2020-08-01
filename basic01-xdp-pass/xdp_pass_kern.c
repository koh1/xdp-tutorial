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

SEC("prog")
int xdp_prog_simple(struct xdp_md *xdp) {
    char fmt[] = "xdp_prog_simple starts.\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    /*
    char fmt2[] = "%u\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), eth->h_source);
    bpf_trace_printk(fmt2, sizeof(fmt2), eth->h_dest);

    __u8 dst_mac[ETH_ALEN];
    __u8 src_mac[ETH_ALEN];
    bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
    bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);


    bpf_trace_printk(fmt2, sizeof(fmt2), eth->h_source);
    bpf_trace_printk(fmt2, sizeof(fmt2), eth->h_dest);

    */
    unsigned long nh_off = sizeof(*eth);
    unsigned int  protocol;
    //  unsigned int  value = 0, *vp;

    if (data + nh_off > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;
        if ((void*)&iph[1] > data_end) {
            return XDP_PASS;
        }
        protocol = iph->protocol;
        if (protocol == 1) {
            char msg[] = "icmp protocol will be dropped\n";
            bpf_trace_printk(msg, sizeof(msg));
            char fmt3[] = "%u\n";
            bpf_trace_printk(fmt3, sizeof(fmt3), iph->saddr);
            bpf_trace_printk(fmt3, sizeof(fmt3), iph->daddr);
            return XDP_DROP;
        } else if (protocol == 6) {
            char msg[] = "tcp\n";
            bpf_trace_printk(msg, sizeof(msg));
        } else if (protocol == 17) {
            char msg[] = "udp\n";
            bpf_trace_printk(msg, sizeof(msg));
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
