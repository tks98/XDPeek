// Include necessary headers for BPF, Ethernet, IP, TCP, UDP, and ICMP protocols
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>

// Define a BPF map to output events
BPF_PERF_OUTPUT(events);

// Define a structure to hold packet information
struct data_t {
    u64 ts;           // Timestamp
    u32 saddr;        // Source IP address
    u32 daddr;        // Destination IP address
    u16 sport;        // Source port
    u16 dport;        // Destination port
    u8 proto;         // Protocol
    u32 pkt_size;     // Total packet size
    u32 payload_len;  // Length of the payload
    char payload[128]; // Payload data (limited to 128 bytes for simplicity)
};

// Main XDP program to trace packets
int trace_packet(struct xdp_md *ctx) {
    // Get pointers to the start and end of the packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Packet too short, pass it on

    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // Not an IP packet, pass it on

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // Packet too short, pass it on

    // Initialize event structure
    struct data_t event = {};
    event.ts = bpf_ktime_get_ns(); // Get current timestamp
    event.saddr = ip->saddr;
    event.daddr = ip->daddr;
    event.proto = ip->protocol;
    event.pkt_size = data_end - data;

    void *payload = NULL;

    // Handle different protocols (TCP, UDP, ICMP)
    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) <= data_end) {
                event.sport = tcp->source;
                event.dport = tcp->dest;
                payload = (void *)(tcp + 1);
            }
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) <= data_end) {
                event.sport = udp->source;
                event.dport = udp->dest;
                payload = (void *)(udp + 1);
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *icmp = (void *)(ip + 1);
            if ((void *)(icmp + 1) <= data_end) {
                event.sport = icmp->un.echo.id;
                event.dport = icmp->un.echo.sequence;
                payload = (void *)(icmp + 1);
            }
            break;
        }
        default:
            // For other protocols, we don't set sport, dport, or payload
            break;
    }

    // Copy payload data if available
    if (payload && payload < data_end) {
        u64 available_payload_len = data_end - payload;
        u64 max_payload_len = sizeof(event.payload);
        if (available_payload_len < max_payload_len) {
            event.payload_len = available_payload_len;
        } else {
            event.payload_len = max_payload_len;
        }
        bpf_probe_read_kernel(&event.payload, event.payload_len, payload);
    }

    // Submit the event to user space
    events.perf_submit(ctx, &event, sizeof(event));

    // Allow the packet to pass through
    return XDP_PASS;
}
