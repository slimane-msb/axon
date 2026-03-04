// SPDX-License-Identifier: GPL-2.0
// axon XDP+TC per-interface L3 firewall
// XDP section kept for native-mode wired NICs (where supported).
// TC section (tc_firewall) is the primary hook: works on lo, wifi, eth, veth.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────
#define MAX_RULES       65536
#define ACTION_PASS     0
#define ACTION_DROP     1
#define ACTION_REDIRECT 2

#define MODE_ALLOW_ALL  0
#define MODE_BLOCK_ALL  1

// ─────────────────────────────────────────────
// Structs
// ─────────────────────────────────────────────
struct ip_key {
    __u32 ifindex;
    __u32 ip;
};

struct drop_event {
    __u32 ifindex;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  rule_type; // 0=explicit, 1=tentative, 2=shared-l7, 3=mode-drop
    __u8  action;
};

// ─────────────────────────────────────────────
// Maps
// ─────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct ip_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct ip_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tentative_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct ip_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shared_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
static __always_inline void emit_event_xdp(
    struct xdp_md *ctx, __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 rule_type, __u8 action)
{
    struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->ifindex   = ctx->ingress_ifindex;
    e->src_ip    = src_ip; e->dst_ip  = dst_ip;
    e->src_port  = src_port; e->dst_port = dst_port;
    e->protocol  = proto; e->rule_type = rule_type; e->action = action;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_event_tc(
    struct __sk_buff *skb, __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 rule_type, __u8 action)
{
    struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    e->ifindex   = skb->ifindex;
    e->src_ip    = src_ip; e->dst_ip  = dst_ip;
    e->src_port  = src_port; e->dst_port = dst_port;
    e->protocol  = proto; e->rule_type = rule_type; e->action = action;
    bpf_ringbuf_submit(e, 0);
}

// ─────────────────────────────────────────────
// TC Ingress — primary firewall hook
// Works on lo, wlp8s0, eth0, veth — every interface type.
// Uses TC_ACT_SHOT to drop, TC_ACT_OK to pass.
// ─────────────────────────────────────────────
SEC("tc")
int tc_firewall(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || (void *)ip + ip_hlen > data_end)
        return TC_ACT_OK;

    __u32 ifindex  = skb->ifindex;
    __u32 dst_ip   = ip->daddr;
    __u32 src_ip   = ip->saddr;
    __u16 src_port = 0, dst_port = 0;
    __u8  proto    = ip->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    __u8 *mode_val = bpf_map_lookup_elem(&mode_map, &ifindex);
    __u8  mode     = mode_val ? *mode_val : MODE_ALLOW_ALL;

    struct ip_key key = { .ifindex = ifindex, .ip = dst_ip };

    // 1. Explicit IP map
    __u8 *explicit_hit = bpf_map_lookup_elem(&blocked_ip_map, &key);
    if (explicit_hit) {
        __u8 action = (mode == MODE_ALLOW_ALL) ? ACTION_DROP : ACTION_PASS;
        emit_event_tc(skb, src_ip, dst_ip, src_port, dst_port, proto, 0, action);
        return (action == ACTION_DROP) ? TC_ACT_SHOT : TC_ACT_OK;
    }

    // 2. Tentative map (FQDN-derived)
    __u8 *tent_hit = bpf_map_lookup_elem(&tentative_map, &key);
    if (tent_hit) {
        emit_event_tc(skb, src_ip, dst_ip, src_port, dst_port, proto, 1, ACTION_DROP);
        return TC_ACT_SHOT;
    }

    // 3. Shared IP map (steer to NFQUEUE for L7 inspection)
    __u8 *shared_hit = bpf_map_lookup_elem(&shared_ip_map, &key);
    if (shared_hit) {
        skb->mark = 0xBEEF;
        emit_event_tc(skb, src_ip, dst_ip, src_port, dst_port, proto, 2, ACTION_REDIRECT);
        return TC_ACT_OK;
    }

    // 4. Default mode
    if (mode == MODE_BLOCK_ALL) {
        emit_event_tc(skb, src_ip, dst_ip, src_port, dst_port, proto, 3, ACTION_DROP);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

// ─────────────────────────────────────────────
// XDP — kept for native-mode wired NICs only.
// Not used on lo or wifi (attached selectively by manager.go).
// ─────────────────────────────────────────────
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || (void *)ip + ip_hlen > data_end)
        return XDP_PASS;

    __u32 ifindex  = ctx->ingress_ifindex;
    __u32 dst_ip   = ip->daddr;
    __u32 src_ip   = ip->saddr;
    __u16 src_port = 0, dst_port = 0;
    __u8  proto    = ip->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    __u8 *mode_val = bpf_map_lookup_elem(&mode_map, &ifindex);
    __u8  mode     = mode_val ? *mode_val : MODE_ALLOW_ALL;

    struct ip_key key = { .ifindex = ifindex, .ip = dst_ip };

    __u8 *explicit_hit = bpf_map_lookup_elem(&blocked_ip_map, &key);
    if (explicit_hit) {
        __u8 action = (mode == MODE_ALLOW_ALL) ? ACTION_DROP : ACTION_PASS;
        emit_event_xdp(ctx, src_ip, dst_ip, src_port, dst_port, proto, 0, action);
        return (action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
    }

    __u8 *tent_hit = bpf_map_lookup_elem(&tentative_map, &key);
    if (tent_hit) {
        emit_event_xdp(ctx, src_ip, dst_ip, src_port, dst_port, proto, 1, ACTION_DROP);
        return XDP_DROP;
    }

    __u8 *shared_hit = bpf_map_lookup_elem(&shared_ip_map, &key);
    if (shared_hit) {
        emit_event_xdp(ctx, src_ip, dst_ip, src_port, dst_port, proto, 2, ACTION_REDIRECT);
        return XDP_PASS;
    }

    if (mode == MODE_BLOCK_ALL) {
        emit_event_xdp(ctx, src_ip, dst_ip, src_port, dst_port, proto, 3, ACTION_DROP);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";