CC = clang
BPF_CFLAGS = -O2 -target bpf -g -I/usr/include/$(shell uname -m)-linux-gnu
LDFLAGS = -lbpf -lelf -lz
INTERFACE = wlp8s0
IP = 185.125.27.16
FILE = ip.txt

all: xdp_block.o block_ip

xdp_block.o: xdp_block.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

block_ip: block_ip.c
	$(CC) -O2 -o $@ $< $(LDFLAGS)

check-interface:
	ip link show $(INTERFACE)

monitor:
	sudo tcpdump -n -i $(INTERFACE) host $(IP)

unset:
	-sudo ip link set dev $(INTERFACE) xdp off

run: all
	sudo ./block_ip $(INTERFACE) 0.0.0.0

add: all
	sudo ./block_ip $(INTERFACE) $(IP) add

add-many: all
	sudo ./block_ip $(INTERFACE) -f $(FILE) add

remove: all
	sudo ./block_ip $(INTERFACE) $(IP) remove

remove-many: all
	sudo ./block_ip $(INTERFACE) -f $(FILE) remove

clean:
	rm -f xdp_block.o block_ip

.PHONY: all clean check-interface monitor unset run add add-many remove remove-many