#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")

int load_balance(struct xdp_md* ctx) {
    // bpf_printk("got a packet\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end) {
    // bpf_printk("ETHERNET\n");
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {
    //   bpf_printk("AJPI\n");  
      if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            // bpf_printk("JUDIPI\n");
            
            bpf_printk("Destination port: %d \n", bpf_ntohs(udp->dest));
      }
    }
  }
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";