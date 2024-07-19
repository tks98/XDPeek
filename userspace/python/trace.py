import subprocess
import socket
import datetime
from bcc import BPF
from bcc.utils import printb
import time
from termcolor import colored
import argparse
import os

# Parse command-line arguments
parser = argparse.ArgumentParser(description="XDPeek")
parser.add_argument('--iface', type=str, default='eth0', help='Network interface to attach to (default: eth0)')
parser.add_argument('--payload', action='store_true', help='Set to true to read packet payloads')
args = parser.parse_args()
interface = args.iface
read_payload = args.payload

# Get system boot time and current time
boot_time_ns = int(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
current_time_ns = int(time.time_ns())

# Define the path to the BPF program file
bpf_file_path = os.path.join(os.path.dirname(__file__), '../../ebpf/xdpeek.c')

# Read the BPF program from the file
try:
    with open(bpf_file_path, 'r') as f:
        bpf_text = f.read()
except FileNotFoundError:
    print(colored(f"Failed to read BPF program file: {bpf_file_path} not found", "red"))
    exit(1)

# Remove existing XDP program
subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "xdp", "off"])

# Define XDP generic mode flag
XDP_FLAGS_SKB_MODE = 2

# Load the BPF program
b = BPF(text=bpf_text)

# Attach the BPF program to the network interface using xdpgeneric mode
b.attach_xdp(interface, fn=b.load_func("trace_packet", BPF.XDP), flags=XDP_FLAGS_SKB_MODE)

# Process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    timestamp_ns = current_time_ns - boot_time_ns + event.ts
    timestamp = timestamp_ns / 1e9
    timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

    proto_str = "TCP" if event.proto == 6 else "UDP" if event.proto == 17 else "ICMP" if event.proto == 1 else str(event.proto)
    src_ip = f"{event.saddr & 0xff}.{(event.saddr >> 8) & 0xff}.{(event.saddr >> 16) & 0xff}.{event.saddr >> 24}"
    dst_ip = f"{event.daddr & 0xff}.{(event.daddr >> 8) & 0xff}.{(event.daddr >> 16) & 0xff}.{event.daddr >> 24}"
    print(f"{timestamp_str} {proto_str} {src_ip}:{socket.ntohs(event.sport)} -> {dst_ip}:{socket.ntohs(event.dport)} {event.pkt_size} bytes")

    if read_payload and event.payload_len > 0:
        payload = bytes(event.payload[:event.payload_len]).decode('utf-8', errors='replace')
        print(f"Payload: {payload}")

# Print header
print(f"Starting packet tracing on {interface}... Press Ctrl-C to end.\n")

# Loop and print events
b["events"].open_perf_buffer(print_event)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nRemoving filter from device")
    b.remove_xdp(interface)