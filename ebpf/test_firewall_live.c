// test_firewall_live.c — live interface tests for xdp_firewall.o
//
// Attaches tc_firewall to a REAL interface via TC/clsact and verifies
// actual packet filtering using UDP sockets. No Go, no shell, no daemon.
//
// Build:
//   gcc -O2 -Wall -o test_firewall_live test_firewall_live.c -lbpf -lelf -lz
//
// Run (root required):
//   sudo ./test_firewall_live /tmp/xdp_firewall.o          # tests on lo only
//   sudo ./test_firewall_live /tmp/xdp_firewall.obj wlp8s0 # also attach-test wlp8s0
//
// What it does:
//   1. Attaches tc_firewall to lo (ifindex=1) using libbpf TC API
//   2. Sends real UDP packets to 127.0.0.1, verifies TC_ACT_SHOT actually drops them
//   3. Tests allow-all passthrough, explicit block, block-all, and mode restoration
//   4. If a second interface is given, verifies attach/detach works on it too
//   5. Cleans up the qdisc on exit (including on SIGINT/SIGTERM)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// ─────────────────────────────────────────────────────────────
// Constants (must match xdp_firewall.c)
// ─────────────────────────────────────────────────────────────
#define MODE_ALLOW_ALL  0
#define MODE_BLOCK_ALL  1

#define TEST_PORT_BASE  49200   // UDP port range used for tests
#define RECV_TIMEOUT_MS  300    // ms to wait for a packet before declaring "dropped"

// ─────────────────────────────────────────────────────────────
// Map key (must match xdp_firewall.c exactly)
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
// Global state for signal-handler cleanup
// ─────────────────────────────────────────────────────────────
static struct bpf_tc_hook g_hooks[8];
static struct bpf_tc_opts g_attach_opts[8];  // opts returned by bpf_tc_attach per hook
static int                g_nhooks = 0;

static void cleanup_all_hooks(void)
{
    for (int i = 0; i < g_nhooks; i++) {
        // bpf_tc_hook_destroy removes the clsact qdisc and all its filters
        bpf_tc_hook_destroy(&g_hooks[i]);
    }
    g_nhooks = 0;
}

static void on_signal(int sig)
{
    (void)sig;
    cleanup_all_hooks();
    printf("\n  [cleanup] TC hooks removed\n");
    _exit(1);
}

// ─────────────────────────────────────────────────────────────
// TC attach / detach
// ─────────────────────────────────────────────────────────────

// Returns hook handle index (for later destroy), or -1 on error.
static int tc_attach(int ifindex, const char *ifname, int prog_fd)
{
    struct bpf_tc_hook hook = {
        .sz           = sizeof(hook),
        .ifindex      = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };

    // Create clsact qdisc (EEXIST is fine — already there from a previous run)
    int ret = bpf_tc_hook_create(&hook);
    if (ret < 0 && ret != -EEXIST) {
        fprintf(stderr, "  bpf_tc_hook_create(%s): %s\n", ifname, strerror(-ret));
        return -1;
    }

    struct bpf_tc_opts opts = {
        .sz      = sizeof(opts),
        .prog_fd = prog_fd,
        .flags   = BPF_TC_F_REPLACE, // replace any existing filter at prio 0
    };

    ret = bpf_tc_attach(&hook, &opts);
    if (ret < 0) {
        fprintf(stderr, "  bpf_tc_attach(%s): %s\n", ifname, strerror(-ret));
        bpf_tc_hook_destroy(&hook);
        return -1;
    }

    // Register for cleanup on signal
    if (g_nhooks < 8) {
        g_hooks[g_nhooks++] = hook;
        g_attach_opts[g_nhooks - 1] = opts; // save for post-attach verification
    }

    printf("  [tc] attached tc_firewall to %s (ifindex=%d)\n", ifname, ifindex);
    return g_nhooks - 1;
}

static void tc_detach(int hook_idx, const char *ifname)
{
    if (hook_idx < 0 || hook_idx >= g_nhooks) return;
    bpf_tc_hook_destroy(&g_hooks[hook_idx]);
    // Shift remaining hooks
    for (int i = hook_idx; i < g_nhooks - 1; i++)
        g_hooks[i] = g_hooks[i + 1];
    g_nhooks--;
    printf("  [tc] detached from %s\n", ifname);
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
// UDP packet helpers
// ─────────────────────────────────────────────────────────────

// Returns a bound UDP receiver socket on 127.0.0.1:port with recv timeout.
static int udp_receiver(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct timeval tv = { .tv_sec = 0, .tv_usec = RECV_TIMEOUT_MS * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Returns 1 if a UDP packet is received within the timeout, 0 if dropped/timeout.
static int udp_send_and_recv(uint16_t port, const char *payload)
{
    int recv_fd = udp_receiver(port);
    if (recv_fd < 0) {
        fprintf(stderr, "  udp_receiver: %s\n", strerror(errno));
        return -1;
    }

    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_fd < 0) { close(recv_fd); return -1; }

    struct sockaddr_in dst = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    sendto(send_fd, payload, strlen(payload), 0,
           (struct sockaddr *)&dst, sizeof(dst));
    close(send_fd);

    char buf[64] = {0};
    ssize_t n = recv(recv_fd, buf, sizeof(buf) - 1, 0);
    close(recv_fd);

    // n > 0 → received (passed), n <= 0 → timeout/error (dropped)
    return n > 0 ? 1 : 0;
}

// Convenience: assert packet is received or dropped
static void expect_pass(const char *name, uint16_t port)
{
    int got = udp_send_and_recv(port, "ping");
    if (got == 1)  PASS(name);
    else           FAIL(name, "packet was dropped (expected pass)");
}

static void expect_drop(const char *name, uint16_t port)
{
    int got = udp_send_and_recv(port, "ping");
    if (got == 0)  PASS(name);
    else           FAIL(name, "packet was passed (expected drop)");
}

// ─────────────────────────────────────────────────────────────
// Test suite: loopback (lo, ifindex=1)
// ─────────────────────────────────────────────────────────────
static void test_lo(int prog_fd, int blocked_fd, int tentative_fd, int mode_fd)
{
    printf("\n── lo (ifindex=1) live packet tests ──\n");

    const int    ifindex = 1;
    const char  *ifname  = "lo";
    uint32_t     lo_ip   = inet_addr("127.0.0.1");
    uint16_t     port    = TEST_PORT_BASE;

    // ── Attach ───────────────────────────────────────────────
    int hook = tc_attach(ifindex, ifname, prog_fd);
    if (hook < 0) {
        FAIL("lo tc_attach", "could not attach TC program");
        return;
    }

    // ── 1. Baseline: allow-all, no rules → packet passes ────
    map_clear_mode(mode_fd, ifindex);
    expect_pass("lo allow-all, no rules → packet passes", port++);

    // ── 2. Explicit block in allow-all mode → packet dropped ─
    // (in allow-all, blocked_ip_map acts as a blacklist)
    map_add_ip(blocked_fd, ifindex, lo_ip);
    expect_drop("lo allow-all + block 127.0.0.1 → TC_ACT_SHOT", port++);

    // ── 3. Remove block → packet passes again ────────────────
    map_del_ip(blocked_fd, ifindex, lo_ip);
    expect_pass("lo allow-all + rule removed → packet passes again", port++);

    // ── 4. Tentative block → packet dropped ──────────────────
    map_add_ip(tentative_fd, ifindex, lo_ip);
    expect_drop("lo tentative block 127.0.0.1 → TC_ACT_SHOT", port++);
    map_del_ip(tentative_fd, ifindex, lo_ip);

    // ── 5. block-all mode, 127.0.0.1 not in allowlist ────────
    // NOTE: this blocks all loopback briefly (~300ms recv timeout)
    map_set_mode(mode_fd, ifindex, MODE_BLOCK_ALL);
    expect_drop("lo block-all, no allowlist → TC_ACT_SHOT", port++);

    // ── 6. block-all + allowlist 127.0.0.1 → passes ─────────
    // (in block-all, blocked_ip_map acts as an allowlist)
    map_add_ip(blocked_fd, ifindex, lo_ip);
    expect_pass("lo block-all + allowlist 127.0.0.1 → packet passes", port++);
    map_del_ip(blocked_fd, ifindex, lo_ip);

    // ── 7. Restore allow-all → normal traffic resumes ────────
    map_clear_mode(mode_fd, ifindex);
    expect_pass("lo allow-all restored → packet passes", port++);

    // ── Detach ───────────────────────────────────────────────
    tc_detach(hook, ifname);

    // ── 8. After detach → packet passes (no filter) ──────────
    expect_pass("lo after TC detach → packet passes (no filter)", port++);
}

// ─────────────────────────────────────────────────────────────
// Test suite: WiFi / other interface (attach + detach only)
// ─────────────────────────────────────────────────────────────
static void test_iface_attach(int prog_fd, const char *ifname)
{
    printf("\n── %s — attach/detach verification ──\n", ifname);

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        FAIL("interface lookup", "%s not found", ifname);
        return;
    }
    printf("  ifindex=%u\n", ifindex);

    // Verify TC filter is not already present
    // (tc filter show dev <ifname> ingress — we check via bpf_tc_query)
    struct bpf_tc_hook qhook = {
        .sz           = sizeof(qhook),
        .ifindex      = (int)ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts qopts = { .sz = sizeof(qopts) };
    int pre = bpf_tc_query(&qhook, &qopts);
    printf("  pre-attach bpf_tc_query: %s\n",
           pre == 0 ? "filter found (stale)" : "no filter (clean)");

    // Attach
    int hook = tc_attach((int)ifindex, ifname, prog_fd);
    if (hook < 0) {
        FAIL("attach tc_firewall", "bpf_tc_attach failed");
        return;
    }
    PASS("attach tc_firewall to real interface");

    // bpf_tc_attach populates opts.prog_id, opts.handle, opts.priority after
    // a successful attach — check prog_id > 0 to confirm the kernel accepted it.
    uint32_t attached_prog_id = g_attach_opts[hook].prog_id;
    if (attached_prog_id > 0) {
        printf("  filter confirmed: prog_id=%u handle=%u prio=%u\n",
               attached_prog_id,
               g_attach_opts[hook].handle,
               g_attach_opts[hook].priority);
        PASS("attach opts confirm filter is present (prog_id > 0)");
    } else {
        FAIL("attach opts confirm filter is present (prog_id > 0)",
             "prog_id is 0 after attach");
    }

    // Detach
    tc_detach(hook, ifname);
    PASS("detach tc_firewall cleanly");

    // Verify OUR specific filter is gone by querying its exact handle + priority.
    // bpf_tc_hook_destroy may leave the clsact qdisc intact if the interface has
    // other TC users (NetworkManager, kernel defaults) — that is correct behaviour.
    // What matters is that our filter entry is no longer present.
    struct bpf_tc_hook qhook_post = {
        .sz           = sizeof(qhook_post),
        .ifindex      = (int)ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts qopts_post = {
        .sz       = sizeof(qopts_post),
        .handle   = g_attach_opts[hook].handle,   // exact handle from attach
        .priority = g_attach_opts[hook].priority, // exact prio  from attach
    };
    int qret_post = bpf_tc_query(&qhook_post, &qopts_post);
    if (qret_post != 0) {
        // ENOENT or any error means the filter slot is gone — detach worked
        PASS("our TC filter gone after detach");
    } else {
        FAIL("our TC filter gone after detach",
             "prog_id=%u still visible at handle=%u prio=%u",
             qopts_post.prog_id, qopts_post.handle, qopts_post.priority);
    }
}

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    const char *obj_path  = argc > 1 ? argv[1] : "/tmp/xdp_firewall.o";
    const char *extra_if  = argc > 2 ? argv[2] : NULL;

    printf("axon live interface tests\n");
    printf("obj:    %s\n", obj_path);
    printf("iface1: lo (ifindex=1) — packet drop/pass tests\n");
    if (extra_if)
        printf("iface2: %s — attach/detach test\n", extra_if);
    printf("\n");

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    // ── Load BPF object ──────────────────────────────────────
    struct bpf_object *obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "bpf_object__open: %s\n", strerror(errno));
        return 1;
    }

    // Disable map pinning — no /sys/fs/bpf writes during tests
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj)
        bpf_map__set_pin_path(map, NULL);

    // Set program types explicitly (SEC("tc") is ambiguous to libbpf)
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
    printf("BPF object loaded\n");

    // Resolve tc program (accept old and new names)
    struct bpf_program *tc_prog =
        bpf_object__find_program_by_name(obj, "tc_firewall");
    if (!tc_prog)
        tc_prog = bpf_object__find_program_by_name(obj, "tc_l7_steer");
    if (!tc_prog) {
        fprintf(stderr, "TC program not found in BPF object\n");
        bpf_object__close(obj);
        return 1;
    }
    printf("TC  prog: %s\n\n", bpf_program__name(tc_prog));

    int tc_fd        = bpf_program__fd(tc_prog);
    int blocked_fd   = bpf_object__find_map_fd_by_name(obj, "blocked_ip_map");
    int tentative_fd = bpf_object__find_map_fd_by_name(obj, "tentative_map");
    int mode_fd      = bpf_object__find_map_fd_by_name(obj, "mode_map");

    if (blocked_fd < 0 || tentative_fd < 0 || mode_fd < 0) {
        fprintf(stderr, "one or more maps not found\n");
        bpf_object__close(obj);
        return 1;
    }

    // ── Run test suites ───────────────────────────────────────
    test_lo(tc_fd, blocked_fd, tentative_fd, mode_fd);

    if (extra_if)
        test_iface_attach(tc_fd, extra_if);

    cleanup_all_hooks(); // belt-and-suspenders

    // ── Summary ───────────────────────────────────────────────
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