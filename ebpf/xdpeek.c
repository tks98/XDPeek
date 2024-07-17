#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 proto;
    u32 pkt_size;
};

int trace_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct data_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.saddr = ip->saddr;
    event.daddr = ip->daddr;
    event.proto = ip->protocol;
    event.pkt_size = data_end - data;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            event.sport = tcp->source;
            event.dport = tcp->dest;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            event.sport = udp->source;
            event.dport = udp->dest;
        }
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)(ip + 1);
        if ((void *)(icmp + 1) <= data_end) {
            event.sport = icmp->un.echo.id;
            event.dport = icmp->un.echo.sequence;
        }
    }

    events.perf_submit(ctx, &event, sizeof(event));
    return XDP_PASS;
}