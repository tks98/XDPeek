# XDPeek

XDPeek is a lightweight network traffic analyzer leveraging XDP (eXpress Data Path) and eBPF (extended Berkeley Packet Filter) for real-time packet inspection and monitoring. It was created as a learning exercise to learn more about XDP and writing more advanced eBPF programs.  

## Overview

The core of XDPeek is an eBPF program written in C, designed to run at the XDP hook in the Linux kernel for high-performance packet processing. The program, named 'trace_packet', is attached to the XDP hook and processes network packets at the earliest possible point in the network stack.

XDPeek includes implementations in both Go and Python for the user-space component, which is responsible for reading and printing the information collected by the eBPF program.

### Sample Output using compiled Go binary with payload enabled tracing a http connection

```bash
sudo -E ./xdpeek -iface enp0s5 --payload=true

Starting packet tracing on interface enp0s5... Press Ctrl-C to end.
2024-07-18 21:50:49.655599 TCP 104.17.24.14:443 -> 10.211.55.5:49438 54 bytes
2024-07-18 21:50:49.656427 TCP 104.17.24.14:443 -> 10.211.55.5:49438 54 bytes
2024-07-18 21:50:49.665212 TCP 146.190.62.39:80 -> 10.211.55.5:58422 803 bytes
Payload: HTTP/1.1 304 Not Modified
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Jul 2024 02:50:50 GMT
Last-Modified: Wed, 22 Mar 2023 1
2024-07-18 21:50:49.794781 TCP 146.190.62.39:80 -> 10.211.55.5:58422 54 bytes
2024-07-18 21:50:49.863437 TCP 146.190.62.39:80 -> 10.211.55.5:58422 803 bytes
Payload: HTTP/1.1 304 Not Modified
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Jul 2024 02:50:50 GMT
Last-Modified: Wed, 22 Mar 2023 1
^C
Removing filter from interface enp0s5
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
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) llvm clang 
```

### Installing System Dependencies on RHEL

```bash
sudo dnf update
sudo dnf install -y bcc-tools kernel-devel llvm clang python3-pip
```

## Running XDPeek

### Golang

```bash
go mod download
sudo -E go run trace.go --iface <network_interface> --payload=true
```

### Python
```bash
pip3 install requirements.txt
sudo -E python3 trace.py --iface <network_interface> --payload
```