#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_PATH 256

// counts packets per its desitnation port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u64);
} udp_pkt_cnt_per_port SEC(".maps");


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
            __u64 timestamp = bpf_ktime_get_ns(); 
            __u16 dst_port = bpf_ntohs(udp->dest);

            __u64 val = 1;

            __u64 *cnt = bpf_map_lookup_elem(&udp_pkt_cnt_per_port, &dst_port);
            if(cnt){
               __sync_fetch_and_add(cnt,1); // tood: researhc if its the best / most efficient way
               val = *cnt;
            }else{
              bpf_map_update_elem(&udp_pkt_cnt_per_port, &dst_port, &val, BPF_ANY);
            }

            bpf_printk("n=%d, dst port: %d  || Arrival: %llu", val, dst_port, timestamp);
      }
    }
  }
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";