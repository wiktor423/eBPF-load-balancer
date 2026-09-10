#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF

#define MAX_PATH 256
/*u8[6]*/
#define DEST_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x70, 0x42, 0xc4}
#define LB_MAC_ADDRESS   {0xbc, 0x24, 0x11, 0x10, 0x30, 0x16}
/*u32*/   
#define DEST_IP_ADDRESS 3232235842 
#define LB_IP_ADDRESS  3232235846 
/*u16*/ 
#define BACKEND_PORT 4321

// counts packets per its desitnation port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u16);
    __type(value, __u64);
} udp_pkt_cnt_per_port SEC(".maps");


static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

// recalculate IPv4 checksum in place
static __always_inline int rewrite_ipv4_csum(struct iphdr *iph) {
    __s64 csum;
    iph->check = 0;

    // calcualte checksum anew using bpf helper 
    // - ip header is small and we change almost all fields
    csum = bpf_csum_diff(0,0, (__be32 *) iph, sizeof(*iph),0);
    if(csum <0)
      return -1;
    iph->check = csum_fold((__u32) csum);

    return 0;
}

// recaluclate UDP checksum using previously known checksum
static __always_inline int rewrite_udp_checksum(
    struct udphdr *udp, __be32 old_saddr, __be32 new_saddr,
    __be32 old_daddr,  __be32 new_daddr,__u32 old_ports,
    __u32 new_ports ){

    __s64 csum;

    if(udp->check == 0) return 0;

    // inverse current checksum
    csum = ~((__u32) udp->check);

    // diff of source address
    csum = bpf_csum_diff(&old_saddr, sizeof(old_saddr), &new_saddr, sizeof(new_saddr), (__u32) csum);
    // diff of destination address
    csum = bpf_csum_diff(&old_daddr, sizeof(old_daddr), &new_daddr, sizeof(new_daddr), (__u32) csum);
    // diff of ports combined for efficient use of 32 bits of diff function
    csum = bpf_csum_diff((__be32 *) &old_ports, sizeof(old_ports), (__be32 *) &new_ports, sizeof(new_ports), (__u32) csum);

    if(csum < 0)
      return -1;

    udp-> check = csum_fold((__u32) csum);
    
    // RFC768 requires 0 to be transmited as all ones
    if (udp->check == 0)
      udp->check=0xffff;

    return 0;
}



SEC("xdp")
int load_balance(struct xdp_md* ctx) {  
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end) {
    
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {

      if(ip->ihl != 5)
        return XDP_PASS; // todo: no support for IPv4 options
      
      
      if(ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return XDP_PASS; //todo: no suport for fragments
      
  
      if (ip->protocol == IPPROTO_UDP) {  
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            __u64 timestamp = bpf_ktime_get_ns(); 
            __u16 dst_port = bpf_ntohs(udp->dest);
            
            if(dst_port != 6767){
              return XDP_PASS; 
            }
            
            bpf_printk("We are on the port 6767");

            if (ip->ttl <= 1)
              return XDP_DROP;
            
            __be32 old_saddr = ip->saddr;
            __be32 old_daddr = ip->daddr;

            bpf_printk("OLD SOURCE ADDRESS: %d\n", old_saddr);
            bpf_printk("OLD DESTINATION ADDRESS: %d\n", old_daddr); 


            __u32 old_ports;
            __builtin_memcpy(&old_ports,&udp->source,sizeof(old_ports));

            __be32 new_saddr = bpf_htonl(LB_IP_ADDRESS); 
            __be32 new_daddr = bpf_htonl(DEST_IP_ADDRESS);

            __be16 new_sport = bpf_htons(6868);
            __be16 new_dport = bpf_htons(BACKEND_PORT);

            ip->ttl--;

            __u32 new_ports;
            __builtin_memcpy( (void*) &new_ports, &new_sport, sizeof(new_sport));
            __builtin_memcpy( (((void*) &new_ports)+2), &new_dport, sizeof(new_dport));
            
            //New addresses assignment 
            u8 source_mac[] = LB_MAC_ADDRESS; 
            bpf_printk("old h_source:");
            for(int i=0; i<6; i++){
              bpf_printk("%x:", eth->h_source[i]);
              (eth->h_source)[i] = source_mac[i];
            }  

            u8 dest_mac[] = DEST_MAC_ADDRESS; 
            bpf_printk("old h_dest:");
            for(int i=0; i<6; i++){
              bpf_printk("%x:", eth->h_dest[i]);
              (eth->h_dest)[i] = dest_mac[i];
            }            

            ip->saddr = new_saddr; 
            ip->daddr = new_daddr; 
            
            udp->source = new_sport;
            udp->dest = new_dport;

              //Checksum validation 
            if (rewrite_udp_checksum(udp, old_saddr, new_saddr, old_daddr, new_daddr, old_ports, new_ports) < 0)           
              return XDP_ABORTED;
            if (rewrite_ipv4_csum(ip) < 0)
              return XDP_ABORTED;
            
            bpf_printk("============================\n");

            bpf_printk("SOURCE MAC ADDRESS: ");
            for(int i=0; i<6; i++){
              bpf_printk("%x:", eth->h_source[i]);
            }

            bpf_printk("\n");                        

            bpf_printk("DESTINATION MAC ADDRESS: ");
            for(int i=0; i<6; i++){
              bpf_printk("%x:", eth->h_dest[i]);
            } 
            bpf_printk("\n");

            bpf_printk("SOURCE IP %d\n", ip->saddr);
            bpf_printk("DESTINATION IP: %d\n", ip->daddr);

            bpf_printk("SOURCE PORT %d\n", udp->source);
            bpf_printk("DESTINATION PORT: %d\n", udp->dest);

            return XDP_TX;
            // __u64 val = 1;

            // __u64 *cnt = bpf_map_lookup_elem(&udp_pkt_cnt_per_port, &dst_port);
            // if(cnt){
            //    __sync_fetch_and_add(cnt,1); // todo: researhc if its the best / most efficient way
            //    val = *cnt;
            // }else{
            //   bpf_map_update_elem(&udp_pkt_cnt_per_port, &dst_port, &val, BPF_ANY);
            // }

            // bpf_printk("n=%d, dst port: %d  || Arrival: %llu", val, dst_port, timestamp);
      }
    }
  }
  }

  //bpf_printk("Just before XDP_TX");
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";