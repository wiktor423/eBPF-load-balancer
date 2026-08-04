# Load Balancer


## Running the LB

Dump vmlinux.h and build the binary

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c main.c -o main.bpf.o
```

Load eBPF to kernel

```bash
sudo bpftool prog load main.bpf.o /sys/fs/bpf/xdp_loadbalancer autoattach
```
(ignore the warning)

attatch it to the Loopback interface

```
sudo ip link set dev lo xdp pinned /sys/fs/bpf/xdp_loadbalancer
```

Logs can be seen in

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Remove after done:
```
sudo ip link set dev lo xdp off
sudo rm /sys/fs/bpf/xdp_loadbalancer
```