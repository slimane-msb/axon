// test_firewall.c — unit tests for xdp_firewall.o
//
// Uses BPF_PROG_TEST_RUN to inject synthetic packets directly into the
// tc_firewall (SCHED_CLS) and xdp_firewall (XDP) programs without attaching
// them to any real interface.
//
// Build:
//   apt install libbpf-dev libelf-dev zlib1g-dev
//   gcc -O2 -Wall -o test_firewall test_firewall.c -lbpf -lelf -lz
//
// Run (root required):
//   sudo ./test_firewall /tmp/xdp_firewall.o
//
// Ifindex notes:
//   TC  — BPF_PROG_TEST_RUN forces loopback (ifindex=1); we use that in maps.
//   XDP — ingress_ifindex is read-only; we don't set ctx_in.
//          test_run uses loopback (ifindex=1) for XDP too; map keys use ifindex=1.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <arpa/inet.h>
#include <linux/bpf.h>      // also defines struct __sk_buff
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────
#define MODE_ALLOW_ALL  0
#define MODE_BLOCK_ALL  1

#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2

// TC return codes from linux/pkt_cls.h: TC_ACT_OK=0, TC_ACT_SHOT=2

// ifindex used in map keys for TC tests
// BPF_PROG_TEST_RUN for SCHED_CLS always runs on loopback (ifindex=1)
#define TC_IFINDEX   1

// ifindex used in map keys for XDP tests
// ingress_ifindex is read-only in XDP; test_run leaves it 0
#define XDP_IFINDEX  1   // test_run uses loopback for XDP too

// ─────────────────────────────────────────────────────────────
// Map key (must match C source exactly)
// ─────────────────────────────────────────────────────────────
struct ip_key {
    uint32_t ifindex;
    uint32_t ip; // network byte order
};

// ─────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define PASS(name) do { \
    tests_run++; tests_passed++; \
    printf("  \033[32m✅ PASS\033[0m  %s\n", name); \
} while(0)

#define FAIL(name, fmt, ...) do { \
    tests_run++; tests_failed++; \
    printf("  \033[31m❌ FAIL\033[0m  %s — " fmt "\n", name, ##__VA_ARGS__); \
} while(0)

#define CHECK(name, got, want) do { \
    if ((got) == (want)) PASS(name); \
    else FAIL(name, "got %d, want %d", (int)(got), (int)(want)); \
} while(0)

// ─────────────────────────────────────────────────────────────
// Packet builders
// ─────────────────────────────────────────────────────────────
static int build_pkt(uint8_t *buf, size_t bufsz,
                     uint16_t ethertype,
                     uint32_t src_ip, uint32_t dst_ip,
                     uint8_t proto,
                     uint16_t src_port, uint16_t dst_port)
{
    memset(buf, 0, bufsz);
    int off = 0;

    struct ethhdr *eth = (struct ethhdr *)buf;
    memset(eth->h_dest,   0xaa, ETH_ALEN);
    memset(eth->h_source, 0xbb, ETH_ALEN);
    eth->h_proto = htons(ethertype);
    off += sizeof(struct ethhdr);

    if (ethertype != ETH_P_IP)
        return off;

    struct iphdr *ip = (struct iphdr *)(buf + off);
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tot_len  = htons((uint16_t)(bufsz - off)); // non-zero
    ip->ttl      = 64;
    ip->protocol = proto;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    off += sizeof(struct iphdr);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(buf + off);
        tcp->source = htons(src_port);
        tcp->dest   = htons(dst_port);
        tcp->doff   = 5;
        off += sizeof(struct tcphdr);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(buf + off);
        udp->source = htons(src_port);
        udp->dest   = htons(dst_port);
        udp->len    = htons(8);
        off += sizeof(struct udphdr);
    }

    return off;
}

// ─────────────────────────────────────────────────────────────
// BPF_PROG_TEST_RUN wrappers
// ─────────────────────────────────────────────────────────────

// TC (SCHED_CLS): no ctx_in — kernel assigns ifindex=1 (loopback) automatically.
// ctx_out uses the real struct __sk_buff so we can read back mark.
static int run_tc(int prog_fd,
                  const uint8_t *pkt, int pkt_len,
                  uint32_t *mark_out)
{
    static uint8_t data_out[512];
    // Use the real __sk_buff from linux/bpf.h — avoids size mismatch (ENOSPC)
    struct __sk_buff ctx_out;
    memset(&ctx_out, 0, sizeof(ctx_out));
    memset(data_out, 0, sizeof(data_out));

    union bpf_attr attr = {};
    attr.test.prog_fd       = prog_fd;
    attr.test.data_in       = (uintptr_t)pkt;
    attr.test.data_size_in  = (uint32_t)pkt_len;
    attr.test.data_out      = (uintptr_t)data_out;
    attr.test.data_size_out = sizeof(data_out);
    attr.test.ctx_out       = (uintptr_t)&ctx_out;
    attr.test.ctx_size_out  = sizeof(ctx_out);
    attr.test.repeat        = 1;

    int ret = syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    if (ret < 0) {
        fprintf(stderr, "  BPF_PROG_TEST_RUN (tc) failed: %s\n", strerror(errno));
        return -1;
    }

    if (mark_out)
        *mark_out = ctx_out.mark;

    return (int)attr.test.retval;
}

// XDP: no ctx_in/ctx_out — ingress_ifindex is read-only (setting it → EINVAL).
// In test_run, the kernel uses loopback as the test device: ingress_ifindex=1.
static int run_xdp(int prog_fd, const uint8_t *pkt, int pkt_len)
{
    static uint8_t data_out[512];
    memset(data_out, 0, sizeof(data_out));

    union bpf_attr attr = {};
    attr.test.prog_fd       = prog_fd;
    attr.test.data_in       = (uintptr_t)pkt;
    attr.test.data_size_in  = (uint32_t)pkt_len;
    attr.test.data_out      = (uintptr_t)data_out;
    attr.test.data_size_out = sizeof(data_out);
    attr.test.repeat        = 1;

    int ret = syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    if (ret < 0) {
        fprintf(stderr, "  BPF_PROG_TEST_RUN (xdp) failed: %s\n", strerror(errno));
        return -1;
    }

    return (int)attr.test.retval;
}

// ─────────────────────────────────────────────────────────────
// Map helpers
// ─────────────────────────────────────────────────────────────
static void map_set_mode(int fd, uint32_t ifindex, uint8_t mode)
{
    bpf_map_update_elem(fd, &ifindex, &mode, BPF_ANY);
}

static void map_clear_mode(int fd, uint32_t ifindex)
{
    bpf_map_delete_elem(fd, &ifindex);
}

static void map_add_ip(int fd, uint32_t ifindex, uint32_t ip_nbo)
{
    struct ip_key k = { .ifindex = ifindex, .ip = ip_nbo };
    uint8_t v = 1;
    bpf_map_update_elem(fd, &k, &v, BPF_ANY);
}

static void map_del_ip(int fd, uint32_t ifindex, uint32_t ip_nbo)
{
    struct ip_key k = { .ifindex = ifindex, .ip = ip_nbo };
    bpf_map_delete_elem(fd, &k);
}

// ─────────────────────────────────────────────────────────────
// TC test suite  (map keys → ifindex=1, kernel-assigned)
// ─────────────────────────────────────────────────────────────
static void test_tc(int prog_fd,
                    int blocked_fd, int tentative_fd,
                    int shared_fd,  int mode_fd)
{
    printf("\n── TC (primary hook, ifindex=%d) ──\n", TC_IFINDEX);

    uint8_t  pkt[256];
    int      pkt_len, ret;
    uint32_t mark;
    uint32_t iface = TC_IFINDEX;

    uint32_t ip_blocked   = inet_addr("10.0.0.1");
    uint32_t ip_tentative = inet_addr("10.0.0.2");
    uint32_t ip_shared    = inet_addr("10.0.0.3");
    uint32_t ip_unknown   = inet_addr("10.0.0.99");
    uint32_t src_ip       = inet_addr("192.168.1.1");

    // 1. allow-all + unknown IP → pass
    map_clear_mode(mode_fd, iface);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_unknown, IPPROTO_UDP, 1234, 5678);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC allow-all, unknown IP → TC_ACT_OK", ret, TC_ACT_OK);

    // 2. allow-all + blocked IP → drop (blacklist mode)
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC allow-all, blocked IP → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(blocked_fd, iface, ip_blocked);

    // 3. block-all + blocked IP → pass (allowlist mode)
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC block-all, allowlisted IP → TC_ACT_OK", ret, TC_ACT_OK);
    map_del_ip(blocked_fd, iface, ip_blocked);
    map_clear_mode(mode_fd, iface);

    // 4. block-all + unknown IP → drop
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_unknown, IPPROTO_UDP, 1234, 443);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC block-all, unknown IP → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_clear_mode(mode_fd, iface);

    // 5. allow-all + tentative IP → always drop
    map_add_ip(tentative_fd, iface, ip_tentative);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_tentative, IPPROTO_TCP, 54321, 443);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC allow-all, tentative IP → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(tentative_fd, iface, ip_tentative);

    // 6. block-all + tentative IP → always drop
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    map_add_ip(tentative_fd, iface, ip_tentative);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_tentative, IPPROTO_TCP, 54321, 80);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC block-all, tentative IP → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(tentative_fd, iface, ip_tentative);
    map_clear_mode(mode_fd, iface);

    // 7. shared IP → pass + mark 0xBEEF
    map_add_ip(shared_fd, iface, ip_shared);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_shared, IPPROTO_TCP, 12345, 443);
    mark = 0;
    ret  = run_tc(prog_fd, pkt, pkt_len, &mark);
    CHECK("TC shared IP → TC_ACT_OK", ret, TC_ACT_OK);
    if (mark == 0xBEEF) PASS("TC shared IP → skb->mark set to 0xBEEF");
    else FAIL("TC shared IP → skb->mark set to 0xBEEF", "got 0x%x", mark);
    map_del_ip(shared_fd, iface, ip_shared);

    // 8. priority: explicit_ip map checked before tentative
    map_add_ip(blocked_fd,   iface, ip_blocked);
    map_add_ip(tentative_fd, iface, ip_blocked); // same IP in both maps
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 53);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    // allow-all + explicit hit → drop (not tentative path)
    CHECK("TC priority: explicit map beats tentative → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(blocked_fd,   iface, ip_blocked);
    map_del_ip(tentative_fd, iface, ip_blocked);

    // 9. non-IP (ARP) → pass regardless of mode
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_ARP, 0, 0, 0, 0, 0);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC non-IP (ARP), block-all → TC_ACT_OK", ret, TC_ACT_OK);
    map_clear_mode(mode_fd, iface);

    // 10. TCP explicit block
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_TCP, 54321, 22);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC TCP explicit block → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(blocked_fd, iface, ip_blocked);

    // 11. UDP explicit block
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 53);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC UDP explicit block → TC_ACT_SHOT", ret, TC_ACT_SHOT);
    map_del_ip(blocked_fd, iface, ip_blocked);

    // 12. iface isolation: rule on iface=2 must not affect iface=1 traffic
    map_add_ip(blocked_fd, 2, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_tc(prog_fd, pkt, pkt_len, NULL);
    CHECK("TC iface isolation: rule on iface=2 doesn't hit iface=1 → TC_ACT_OK", ret, TC_ACT_OK);
    map_del_ip(blocked_fd, 2, ip_blocked);
}

// ─────────────────────────────────────────────────────────────
// XDP test suite  (map keys → ifindex=0, test_run default)
// ─────────────────────────────────────────────────────────────
static void test_xdp(int prog_fd,
                     int blocked_fd, int tentative_fd,
                     int shared_fd,  int mode_fd)
{
    printf("\n── XDP (wired-native fallback, ifindex=%d) ──\n", XDP_IFINDEX);

    uint8_t  pkt[256];
    int      pkt_len, ret;
    uint32_t iface = XDP_IFINDEX;

    uint32_t ip_blocked   = inet_addr("10.1.0.1");
    uint32_t ip_tentative = inet_addr("10.1.0.2");
    uint32_t ip_shared    = inet_addr("10.1.0.3");
    uint32_t ip_unknown   = inet_addr("10.1.0.99");
    uint32_t src_ip       = inet_addr("192.168.2.1");

    // 13. allow-all + unknown IP → pass
    map_clear_mode(mode_fd, iface);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_unknown, IPPROTO_UDP, 1234, 5678);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP allow-all, unknown IP → XDP_PASS", ret, XDP_PASS);

    // 14. allow-all + blocked IP → drop
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP allow-all, blocked IP → XDP_DROP", ret, XDP_DROP);
    map_del_ip(blocked_fd, iface, ip_blocked);

    // 15. block-all + blocked IP → pass (allowlist)
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    map_add_ip(blocked_fd, iface, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP block-all, allowlisted IP → XDP_PASS", ret, XDP_PASS);
    map_del_ip(blocked_fd, iface, ip_blocked);
    map_clear_mode(mode_fd, iface);

    // 16. block-all + unknown IP → drop
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_unknown, IPPROTO_UDP, 1234, 443);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP block-all, unknown IP → XDP_DROP", ret, XDP_DROP);
    map_clear_mode(mode_fd, iface);

    // 17. allow-all + tentative IP → always drop
    map_add_ip(tentative_fd, iface, ip_tentative);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_tentative, IPPROTO_TCP, 54321, 443);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP allow-all, tentative IP → XDP_DROP", ret, XDP_DROP);
    map_del_ip(tentative_fd, iface, ip_tentative);

    // 18. block-all + tentative IP → always drop
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    map_add_ip(tentative_fd, iface, ip_tentative);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_tentative, IPPROTO_TCP, 54321, 80);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP block-all, tentative IP → XDP_DROP", ret, XDP_DROP);
    map_del_ip(tentative_fd, iface, ip_tentative);
    map_clear_mode(mode_fd, iface);

    // 19. allow-all + shared IP → pass (steered to L7 via TC/NFQUEUE)
    map_add_ip(shared_fd, iface, ip_shared);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_shared, IPPROTO_TCP, 12345, 443);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP allow-all, shared IP → XDP_PASS (steer to L7)", ret, XDP_PASS);
    map_del_ip(shared_fd, iface, ip_shared);

    // 20. non-IP (ARP) → always pass
    map_set_mode(mode_fd, iface, MODE_BLOCK_ALL);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_ARP, 0, 0, 0, 0, 0);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP non-IP (ARP), block-all → XDP_PASS", ret, XDP_PASS);
    map_clear_mode(mode_fd, iface);

    // 21. truncated packet (1 byte) → pass (bounds check fails gracefully)
    uint8_t tiny[14] = {0}; // shorter than ethhdr
    ret = run_xdp(prog_fd, tiny, sizeof(tiny) - 1);
    CHECK("XDP truncated packet → XDP_PASS", ret, XDP_PASS);

    // 22. iface isolation: rule on iface=2 must not affect XDP traffic on iface=1
    map_add_ip(blocked_fd, 2, ip_blocked);
    pkt_len = build_pkt(pkt, sizeof(pkt), ETH_P_IP, src_ip, ip_blocked, IPPROTO_UDP, 1234, 80);
    ret = run_xdp(prog_fd, pkt, pkt_len);
    CHECK("XDP iface isolation: rule on iface=2 doesn't hit iface=1 → XDP_PASS",
          ret, XDP_PASS);
    map_del_ip(blocked_fd, 2, ip_blocked);
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    const char *obj_path = argc > 1 ? argv[1] : "/tmp/xdp_firewall.o";

    printf("axon BPF unit tests\n");
    printf("obj:  %s\n", obj_path);
    printf("TC  ifindex: %d  (loopback — fixed by BPF_PROG_TEST_RUN for SCHED_CLS)\n", TC_IFINDEX);
    printf("XDP ifindex: %d  (ingress_ifindex read-only; test_run uses loopback=1 for XDP too)\n", XDP_IFINDEX);

    struct bpf_object *obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return 1;
    }

    // Disable map pinning — tests must not touch /sys/fs/bpf
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj)
        bpf_map__set_pin_path(map, NULL);

    // SEC("tc") is ambiguous — set types explicitly before load.
    // Accept both program names for compatibility with old/new .o files.
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        const char *name = bpf_program__name(p);
        if (strcmp(name, "tc_firewall") == 0 ||
            strcmp(name, "tc_l7_steer") == 0) {
            bpf_program__set_type(p, BPF_PROG_TYPE_SCHED_CLS);
        } else if (strcmp(name, "xdp_firewall") == 0) {
            bpf_program__set_type(p, BPF_PROG_TYPE_XDP);
        }
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("BPF object loaded (pinning disabled)\n");

    // Resolve program FDs
    struct bpf_program *tc_prog =
        bpf_object__find_program_by_name(obj, "tc_firewall");
    if (!tc_prog)
        tc_prog = bpf_object__find_program_by_name(obj, "tc_l7_steer");

    struct bpf_program *xdp_prog =
        bpf_object__find_program_by_name(obj, "xdp_firewall");

    if (!tc_prog)  { fprintf(stderr, "tc program not found\n");  return 1; }
    if (!xdp_prog) { fprintf(stderr, "xdp program not found\n"); return 1; }

    const char *tc_name = bpf_program__name(tc_prog);
    printf("TC  prog: %s\n", tc_name);
    printf("XDP prog: %s\n", bpf_program__name(xdp_prog));

    if (strcmp(tc_name, "tc_l7_steer") == 0)
        printf("NOTE: testing old tc_l7_steer — recompile .c for full tc_firewall logic\n");

    int tc_fd  = bpf_program__fd(tc_prog);
    int xdp_fd = bpf_program__fd(xdp_prog);

    int blocked_fd   = bpf_object__find_map_fd_by_name(obj, "blocked_ip_map");
    int tentative_fd = bpf_object__find_map_fd_by_name(obj, "tentative_map");
    int shared_fd    = bpf_object__find_map_fd_by_name(obj, "shared_ip_map");
    int mode_fd      = bpf_object__find_map_fd_by_name(obj, "mode_map");

    if (blocked_fd < 0 || tentative_fd < 0 || shared_fd < 0 || mode_fd < 0) {
        fprintf(stderr, "one or more maps not found\n");
        bpf_object__close(obj);
        return 1;
    }

    test_tc (tc_fd,  blocked_fd, tentative_fd, shared_fd, mode_fd);
    test_xdp(xdp_fd, blocked_fd, tentative_fd, shared_fd, mode_fd);

    printf("\n────────────────────────────────────────\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (\033[31m%d FAILED\033[0m)", tests_failed);
    else
        printf("  \033[32m(all pass)\033[0m");
    printf("\n────────────────────────────────────────\n");

    bpf_object__close(obj);
    return tests_failed > 0 ? 1 : 0;
}