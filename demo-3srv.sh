#!/usr/bin/env bash

set -euo pipefail

SESSION="lb-dev-remote"

sudo -v

error_handler() {
        local line_no=$1
        local exit_code=$2
        echo "CRITICAL: Script crashed at line ${line_no} with exit code ${exit_code}."
}
trap 'error_handler ${LINENO} $?' ERR

# zakladamyh ze jest cloned w /home/debian/eBPF-load-balanceer
# na kazdy servie git pull -> recompile

JUMPHOST='ubusrva1.bass-tone.ts.net'
CLNT_HOSTNAME="debian01"
EBPF_HOSTNAME="debian03"
SRV_HOSTNAME="debian05"

# ================================================
SERVER_CMD="clear; echo ''; echo '';  echo '################'; echo '#### SERVER ####'; echo '################'; echo ''; echo ''; ssh -t -J $JUMPHOST  $SRV_HOSTNAME \"sudo -u debian bash -c 'cd ~/eBPF-load-balancer; git checkout feature/packet_return && git pull origin feature/packet_return; cd server; gcc ./main.c -o server && ./server'\" "

CLIENT_CMD="clear; echo ''; echo '';  echo '################'; echo '#### CLIENT ####'; echo '################'; echo ''; echo ''; ssh -t -J $JUMPHOST  $CLNT_HOSTNAME \"sudo -u debian bash -c 'cd ~/eBPF-load-balancer; git checkout feature/packet_return && git pull origin feature/packet_return; cd client; gcc ./main.c -o client && SERVER_PORT=6767 SERVER_ADDRESS="192.168.1.70" ./client'\" "

EBPF_CMD="ssh -t -J $JUMPHOST $EBPF_HOSTNAME \"sudo -u debian bash -c 'cd ~/eBPF-load-balancer; git pull; cd ebp-lb; { [ -f vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; } && { sudo ip link set dev eth0 xdp off 2>/dev/null || true; } && { sudo ip link set dev eth0 xdp off || true; } && { sudo rm -f /sys/fs/bpf/xdp_loadbalancer || true; } && clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c main.c -o main.bpf.o && sudo bpftool prog load main.bpf.o /sys/fs/bpf/xdp_loadbalancer autoattach && sudo ip link set dev eth0 xdp pinned /sys/fs/bpf/xdp_loadbalancer && sudo cat /sys/kernel/debug/tracing/trace_pipe' \" "
# ' 

# ================================================

tmux kill-session -t "$SESSION" 2>/dev/null || true
PANE_SERVER=$(tmux new-session -d -s "$SESSION" -P -F '#{pane_id}')

# Layout: pane 0 = left 25%, pane 1 = middle 50%, pane 2 = right 25%
PANE_EBPF=$(tmux split-window -h -l 75% -t "$PANE_SERVER" -P -F '#{pane_id}')
PANE_CLIENT=$(tmux split-window -h -l 33% -t "$PANE_EBPF" -P -F '#{pane_id}')

tmux send-keys -t "$PANE_SERVER" "$SERVER_CMD" C-m
tmux send-keys -t "$PANE_EBPF" "$EBPF_CMD" C-m
tmux send-keys -t "$PANE_CLIENT" "$CLIENT_CMD" C-m

tmux select-pane -t "$PANE_EBPF"
tmux attach -t "$SESSION"