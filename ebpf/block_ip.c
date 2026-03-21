#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

void update_ip(int fd, const char *ip_str, const char *cmd) {
    __u32 ip_addr;
    if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) return;
    if (strcmp(cmd, "remove") == 0) {
        bpf_map_delete_elem(fd, &ip_addr);
    } else {
        __u8 val = 1;
        bpf_map_update_elem(fd, &ip_addr, &val, BPF_ANY);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;

    const char *ifname = argv[1];
    unsigned int ifindex = if_nametoindex(ifname);

    struct bpf_object *obj = bpf_object__open_file("xdp_block.o", NULL);
    if (!obj || libbpf_get_error(obj)) return 1;
    if (bpf_object__load(obj)) return 1;

    int map_fd = bpf_object__find_map_fd_by_name(obj, "blacklist");
    
    if (strcmp(argv[2], "-f") == 0 && argc == 5) {
        FILE *f = fopen(argv[3], "r");
        if (!f) return 1;
        char line[64];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = 0;
            update_ip(map_fd, line, argv[4]);
        }
        fclose(f);
    } else {
        const char *cmd = (argc > 3) ? argv[3] : "add";
        update_ip(map_fd, argv[2], cmd);
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    return bpf_set_link_xdp_fd(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE);
}