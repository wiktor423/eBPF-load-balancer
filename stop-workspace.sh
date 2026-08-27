#!/usr/bin/env bash
# Tear down the dev session and detach/unpin the XDP program
set -uo pipefail

SESSION="${SESSION:-lb-dev}"
IFACE="${IFACE:-lo}"
PIN="/sys/fs/bpf/xdp_loadbalancer"

sudo ip link set dev "$IFACE" xdp off
sudo rm -f "$PIN"

echo "XDP detached from $IFACE and $PIN removed"
tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed tmux session $SESSION"
