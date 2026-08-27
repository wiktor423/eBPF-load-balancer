#!/usr/bin/env bash

set -euo pipefail

SESSION="lb-dev"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ================================================
SERVER_CMD="clear; echo ''; echo '';  echo '################'; echo '#### SERVER ####'; echo '################'; echo ''; echo ''; gcc ./main.c -o server && ./server"
CLIENT_CMD="clear; echo ''; echo '';  echo '################'; echo '#### CLIENT ####'; echo '################'; echo ''; echo '';  gcc ./main.c -o client && ./client"
IFACE="${IFACE:-lo}"
PIN="/sys/fs/bpf/xdp_loadbalancer"
# ================================================

# Cache sudo credentials once
sudo -v

EBPF_CMD="cd '$ROOT/ebp-lb' \
&& { [ -f vmlinux.h ] || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; } \
&& clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -c main.c -o main.bpf.o \
&& sudo bpftool prog load main.bpf.o $PIN autoattach \
&& sudo ip link set dev $IFACE xdp pinned $PIN \
&& sudo cat /sys/kernel/debug/tracing/trace_pipe"

# Start fresh
tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -c "$ROOT/server"

# Layout: pane 0 = left 25%, pane 1 = middle 50%, pane 2 = right 25%
tmux split-window -h -l 75% -t "$SESSION:0.0" -c "$ROOT/ebp-lb"
tmux split-window -h -l 33% -t "$SESSION:0.1" -c "$ROOT/client"

tmux send-keys -t "$SESSION:0.0" "$SERVER_CMD" C-m
tmux send-keys -t "$SESSION:0.1" "$EBPF_CMD" C-m
tmux send-keys -t "$SESSION:0.2" "$CLIENT_CMD" C-m

tmux select-pane -t "$SESSION:0.1"
tmux attach -t "$SESSION"