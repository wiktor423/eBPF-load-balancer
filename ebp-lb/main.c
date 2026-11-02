#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF

#define MAX_PATH 256

/*u8[6]*/
#define CLIENT1_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x28, 0xf8, 0x53}
#define CLIENT2_MAC_ADDRESS {0xbc, 0x24, 0x11, 0xd4, 0x9d, 0xd4}

#define LB_MAC_ADDRESS   {0xbc, 0x24, 0x11, 0x10, 0x30, 0x16}

#define BACKEND1_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x5c, 0xbe, 0x07}
#define BACKEND2_MAC_ADDRESS {0xbc, 0x24, 0x11, 0x70, 0x42, 0xc4}
#define BACKEND3_MAC_ADDRESS {0xbc, 0x24, 0x11, 0xe4, 0x67, 0x36}

/*u32*/   
#define CLIENT1_IP_ADDRESS 3232235844       //debian01 192.168.1.68
#define CLIENT2_IP_ADDRESS 3232235845       //debian02 192.168.1.69

#define LB_IP_ADDRESS  3232235846           //debian03 192.168.1.70 

#define BACKEND1_IP_ADDRESS 3232235847      //debian04 192.168.1.71
#define BACKEND2_IP_ADDRESS 3232235842      //debian05 192.168.1.66
#define BACKEND3_IP_ADDRESS 3232235843      //debian06 192.168.1.67

/*u16*/
#define LB_PORT 6767 
#define BACKEND_PORT 4321 

// ========================================
// todo: make it a per-backend map (more connections, etc)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16); // dport
    __type(value, __u32); // client IP
} backend_connections SEC(".maps");
// ========================================

// ip -> mac
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // ipv4
    __type(value, __u8[6]); // mac
} ip_to_mac SEC(".maps");

// normally should be a CIDR check
// NOTE: assumes ip is in host byte order (after ntohl)
// todo: set proper type
static bool __always_inline _is_backend_ip(__u32 ip){ return ip == BACKEND1_IP_ADDRESS || ip == BACKEND2_IP_ADDRESS || ip == BACKEND3_IP_ADDRESS; }
static bool __always_inline _is_client_ip(__u32 ip){ return ip == CLIENT1_IP_ADDRESS || ip == CLIENT2_IP_ADDRESS; }

static __always_inline void _set_connection_ip(__u16 dport, __u32 ip){ bpf_map_update_elem(&backend_connections, &dport, &ip, BPF_ANY); }
static __always_inline __u32* _get_connection_ip(__u16 dport){ return bpf_map_lookup_elem(&backend_connections, &dport); }

static  __always_inline int _set_mac(__u32 ip, __u8 mac[6]){ return bpf_map_update_elem(&ip_to_mac, &ip, mac, BPF_ANY); }
static __always_inline __u8* _get_mac(__u32 ip){ return bpf_map_lookup_elem(&ip_to_mac, &ip); }

__u64 backend = 0; 
static __always_inline __u32 _choose_backend_ip(){
  // round robin
  backend +=1;
  switch (backend)
  {
  case 1:
    return BACKEND1_IP_ADDRESS;
    break;
  
  default:
    backend = 0;
    return BACKEND2_IP_ADDRESS;
  }
}

// hack - we need to have backends' macs inside the map
// todo: find a way to prefill it once
static __always_inline void prefil_mac_map(){
  __u8 mac1[6] = BACKEND1_MAC_ADDRESS; _set_mac(BACKEND1_IP_ADDRESS, mac1);
  __u8 mac2[6] = BACKEND2_MAC_ADDRESS; _set_mac(BACKEND2_IP_ADDRESS, mac2);
  __u8 mac3[6] = BACKEND3_MAC_ADDRESS; _set_mac(BACKEND3_IP_ADDRESS, mac3);
}

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

            // return path: backend -> lb
            if( new_sport == bpf_htons(4321) && _is_backend_ip(bpf_ntohl(old_saddr)) ){
                // 1. dport stays the same - EPHEMERAL port from client
                // 2. sport -> 6767
                new_sport = bpf_htons(LB_PORT); // not sure if we need to do that 
                  
                // 3. sip -> LB_ip - done below
                // 4. dip -> client_n ip
                __u32* p_daddr = _get_connection_ip(new_dport); //todo: for now only allows 65 535 connections -> add mapping from sorce ip
                if (!p_daddr)
                  return XDP_PASS;

                new_daddr = *p_daddr;

                // 5. dmac -> client_n mac
                prefil_mac_map(); //todo: find a way to do this less often
                __u8* mac = _get_mac(new_dport);
                if(!mac)
                  return XDP_PASS;
                
                __builtin_memcpy(dest_mac, mac, 6);

                // 6. smac -> LB_mac
                  // done higher up - same for both dorections
                
                // todo: 7. remove connection from maps
                bpf_printk("debug: out return branch");
            }            
            // forward path: client -> lb
            else if(new_dport == bpf_htons(6767)  && _is_client_ip(bpf_ntohl(old_saddr) ) ){
              // 1. dport -> 4321
                new_dport = bpf_htons(BACKEND_PORT);
              // 2. sport -> stays the same - EPHEMERAL PORT
                // but we save mapping port -> client ip
                _set_connection_ip(new_sport, old_saddr);
                _set_mac(new_sport, eth->h_source);
              
              // 3. sip -> LB_ip - done below
              // 4. dip -> backend ip
                new_daddr = _choose_backend_ip();
              
              // 5. dmac -> backend mac
                prefil_mac_map(); //todo: find a way to do this less often
                __u8* mac = _get_mac(new_daddr);
                if(!mac)
                  return XDP_PASS;
                new_daddr = bpf_htonl(new_daddr);
                  
                __builtin_memcpy(dest_mac, mac, 6); 
              // 6. smac -> LB_mac
                  // done higher up - same for both dorections
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

            bpf_printk("SOURCE IP %d\n", bpf_ntohl(ip->saddr));
            bpf_printk("DESTINATION IP: %d\n", bpf_ntohl(ip->daddr));

            bpf_printk("SOURCE PORT %d\n", bpf_ntohs(udp->source));
            bpf_printk("DESTINATION PORT: %d\n",  bpf_ntohs(udp->dest));

            return XDP_TX;
      }
    }
  }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";