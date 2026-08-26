#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")

int load_balance(struct xdp_md* ctx) {
    bpf_printk("got a packet\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end) {
    bpf_printk("ETHERNET\n");
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {
      bpf_printk("AJPI\n");  
      if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            bpf_printk("JUDIPI\n");
            unsigned short int port = 22;
            //bpf_ntohs(udp->dest)
            bpf_printk("Destination port: 22\n");
            
        //   if (udp->dest == ntohs(90)) {
        //     bpf_trace_printk("tcp  port 90\n");
        //     tcp->dest = ntohs(80);
        //     tcp->check=0;
        //     tcp->check = checksum((unsigned short *)tcp, sizeof(struct tcphdr));
        //     }
        // }
      }
    }
  }
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";