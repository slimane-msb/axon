#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IP_LEN 64
#define CMD_LEN 512

void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
        str[len - 1] = '\0';
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <ip_file>\n", argv[0]);
        return 1;
    }

    char *interface = argv[1];
    char *filename = argv[2];

    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    char ip[MAX_IP_LEN];
    char command[CMD_LEN];

    while (fgets(ip, sizeof(ip), file)) {

        trim_newline(ip);
        if (strlen(ip) == 0)
            continue;

        /* -------- INPUT chain -------- */

        // Log incoming packets from IP
        snprintf(command, sizeof(command),
                 "iptables -A INPUT -i %s -s %s "
                 "-m limit --limit 10/min "
                 "-j LOG --log-prefix \"L3BLOCK_IN_SRC: \" --log-level 4",
                 interface, ip);
        system(command);

        // Drop incoming packets from IP
        snprintf(command, sizeof(command),
                 "iptables -A INPUT -i %s -s %s -j DROP",
                 interface, ip);
        system(command);

        /* -------- OUTPUT chain -------- */

        // Log outgoing packets to IP
        snprintf(command, sizeof(command),
                 "iptables -A OUTPUT -o %s -d %s "
                 "-m limit --limit 10/min "
                 "-j LOG --log-prefix \"L3BLOCK_OUT_DST: \" --log-level 4",
                 interface, ip);
        system(command);

        // Drop outgoing packets to IP
        snprintf(command, sizeof(command),
                 "iptables -A OUTPUT -o %s -d %s -j DROP",
                 interface, ip);
        system(command);

        /* -------- FORWARD chain (if router) -------- */

        snprintf(command, sizeof(command),
                 "iptables -A FORWARD -i %s -s %s "
                 "-m limit --limit 10/min "
                 "-j LOG --log-prefix \"L3BLOCK_FWD_SRC: \" --log-level 4",
                 interface, ip);
        system(command);

        snprintf(command, sizeof(command),
                 "iptables -A FORWARD -i %s -s %s -j DROP",
                 interface, ip);
        system(command);

        snprintf(command, sizeof(command),
                 "iptables -A FORWARD -o %s -d %s "
                 "-m limit --limit 10/min "
                 "-j LOG --log-prefix \"L3BLOCK_FWD_DST: \" --log-level 4",
                 interface, ip);
        system(command);

        snprintf(command, sizeof(command),
                 "iptables -A FORWARD -o %s -d %s -j DROP",
                 interface, ip);
        system(command);

        printf("Blocking and logging IP: %s on %s\n", ip, interface);
    }

    fclose(file);
    return 0;
}