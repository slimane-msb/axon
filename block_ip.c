#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

int main(int argc, char **argv) {
    if (argc < 3) return 1;

    const char *ifname = argv[1];
    const char *ip_str = argv[2];
    const char *cmd = (argc > 3) ? argv[3] : "add";
    
    unsigned int ifindex = if_nametoindex(ifname);
    __u32 ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);

    struct bpf_object *obj = bpf_object__open_file("xdp_block.o", NULL);
    if (!obj || libbpf_get_error(obj)) return 1;
    if (bpf_object__load(obj)) return 1;

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "blacklist");
    int map_fd = bpf_map__fd(map);

    if (strcmp(cmd, "remove") == 0) {
        bpf_map_delete_elem(map_fd, &ip_addr);
    } else if (ip_addr != 0) {
        __u8 val = 1;
        bpf_map_update_elem(map_fd, &ip_addr, &val, BPF_ANY);
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    return bpf_set_link_xdp_fd(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE);
}