# XDPeek

XDPeek is a lightweight network traffic analyzer leveraging XDP (eXpress Data Path) and eBPF (extended Berkeley Packet Filter) for real-time packet inspection and monitoring.

## Overview

The core of XDPeek is an eBPF program written in C, designed to run in the kernel for high-performance packet processing. This program captures packet metadata such as timestamps, source and destination IP addresses, ports, protocols, and packet sizes. The captured data is then forwarded to user space for further processing and display.

XDPeek includes implementations in both Go and Python for the user-space component, which is responsible for reading and printing the information collected by the eBPF program.

### Sample Output using compiled binary

```bash
sudo -E ./xdpeek -iface enp0s5

Starting packet tracing on interface enp0s5... Press Ctrl-C to end.
2024-07-16 23:22:27.794486 TCP 51.11.192.49:443 -> 10.211.55.5:52640 54 bytes
2024-07-16 23:22:27.794521 TCP 51.11.192.49:443 -> 10.211.55.5:52640 54 bytes
2024-07-16 23:22:27.794531 TCP 51.11.192.49:443 -> 10.211.55.5:52640 54 bytes
2024-07-16 23:22:27.818859 UDP 10.211.55.1:53 -> 10.211.55.5:34655 223 bytes
2024-07-16 23:22:27.818883 UDP 10.211.55.1:53 -> 10.211.55.5:56856 274 bytes
2024-07-16 23:22:27.871207 UDP 10.211.55.1:53 -> 10.211.55.5:41166 190 bytes
2024-07-16 23:22:27.916230 TCP 51.11.192.49:443 -> 10.211.55.5:52640 93 bytes
2024-07-16 23:22:28.031859 TCP 51.11.192.49:443 -> 10.211.55.5:52640 148 bytes
2024-07-16 23:22:28.033278 TCP 51.11.192.49:443 -> 10.211.55.5:52640 54 bytes
2024-07-16 23:22:28.088439 TCP 10.42.0.194:9000 -> 10.211.55.5:43564 54 bytes
```

## Kernel and OS Prerequisites

To compile and run XDPeek, you need a Linux system with the following:

1. **Linux Kernel**: Version 4.18 or later (5.x recommended)
2. **BCC (BPF Compiler Collection)**: Tools and libraries for working with eBPF
3. **LLVM and Clang**: Required for compiling eBPF programs
4. **Linux Headers**: Matching headers for your running kernel

### Installing System Dependencies on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) llvm clang python3-pip
```

## Running XDPeek

### Golang

```bash
go mod download
sudo -E go run trace.go -iface <network_interface>
```

### Python
```bash
pip3 install requirements.txt
sudo -E python3 trace.py --iface <network_interface>
```