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
# Use pane IDs rather than numeric indexes so base-index/pane-base-index don't matter
PANE_SERVER=$(tmux new-session -d -s "$SESSION" -c "$ROOT/server" -P -F '#{pane_id}')

# Layout: server = left 25%, ebpf = middle 50%, client = right 25%
PANE_EBPF=$(tmux split-window -h -l 75% -t "$PANE_SERVER" -c "$ROOT/ebp-lb" -P -F '#{pane_id}')
PANE_CLIENT=$(tmux split-window -h -l 33% -t "$PANE_EBPF" -c "$ROOT/client" -P -F '#{pane_id}')

tmux send-keys -t "$PANE_SERVER" "$SERVER_CMD" C-m
tmux send-keys -t "$PANE_EBPF" "$EBPF_CMD" C-m
tmux send-keys -t "$PANE_CLIENT" "$CLIENT_CMD" C-m

tmux select-pane -t "$PANE_EBPF"
tmux attach -t "$SESSION"