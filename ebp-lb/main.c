#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF

#define MAX_PATH 256

/*u8[6]*/
#define SERV_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x70, 0x42, 0xc4}
#define LB_MAC_ADDRESS   {0xbc, 0x24, 0x11, 0x10, 0x30, 0x16}
#define CLIENT_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x28, 0xf8, 0x53}

/*u32*/   
#define SERV_IP_ADDRESS 3232235842 
#define LB_IP_ADDRESS  3232235846 
#define CLIENT_IP_ADDRESS 3232235844

/*u16*/
#define LB_PORT 6767 
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
            if (ip->ttl <= 1)
              return XDP_DROP;
           
          //__u16 dst_port = bpf_ntohs(udp->dest);
           __be32 old_saddr = ip->saddr;
           __be32 old_daddr = ip->daddr;

           __be32 new_daddr;
           __be16 new_sport = udp->source;   
           __be16 new_dport = udp->dest;     
           u8 source_mac[6] = LB_MAC_ADDRESS;  //same for both directions
           u8 dest_mac[6];   

           /*
              Reply from the backend comes with the ephemeral port of the client, therefore 
              there is no need to change or save it 
           */

            if(bpf_ntohl(old_saddr) == SERV_IP_ADDRESS){
                new_daddr = bpf_htonl(CLIENT_IP_ADDRESS);
                new_sport = bpf_htons(LB_PORT); // not sure if we need to do that 
                __u8 mac[6] = CLIENT_MAC_ADDRESS;
                __builtin_memcpy(dest_mac, mac, 6);
            }
            
            else if(bpf_ntohl(old_saddr) == CLIENT_IP_ADDRESS){
                new_daddr = bpf_htonl(SERV_IP_ADDRESS); 
                new_dport = bpf_htons(BACKEND_PORT);
                __u8 mac[6] = SERV_MAC_ADDRESS;
                __builtin_memcpy(dest_mac, mac, 6); 
            } 
            
            // If it is not coming from the client or the backend then pass
            else{
              return XDP_PASS;
            }

            ip->ttl--;
                       
            bpf_printk("OLD SOURCE ADDRESS: %d\n", old_saddr);
            bpf_printk("OLD DESTINATION ADDRESS: %d\n", old_daddr); 

            __u32 old_ports;
            __builtin_memcpy(&old_ports,&udp->source,sizeof(old_ports)); // not sure if we need this anymore
            __be32 new_saddr = bpf_htonl(LB_IP_ADDRESS);   
            
            __builtin_memcpy(eth->h_source, source_mac, 6);
            __builtin_memcpy(eth->h_dest, dest_mac, 6);

            ip->saddr = new_saddr; 
            ip->daddr = new_daddr; 
            
            udp->source = new_sport;
            udp->dest = new_dport;
            __u32 new_ports;
            __builtin_memcpy(&new_ports, &udp->source, sizeof(new_ports));

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
      }
    }
  }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";