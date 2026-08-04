#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int load_balance(struct xdp_md* ctx) {
    bpf_printk("packet arrived\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";