.PHONY: add-nftable rm-nftable list-nftable

add-nftable:
	-sudo iptables -N AXON_SINKHOLE
	-sudo iptables -I OUTPUT 1 -j AXON_SINKHOLE
	-sudo iptables -I FORWARD 1 -j AXON_SINKHOLE
	sudo iptables -A AXON_SINKHOLE -p udp --dport 53  -j NFQUEUE --queue-num 0
	sudo iptables -A AXON_SINKHOLE -p udp --dport 443 -j NFQUEUE --queue-num 0
	sudo iptables -A AXON_SINKHOLE -p tcp --dport 53  -j NFQUEUE --queue-num 0
	sudo iptables -A AXON_SINKHOLE -p tcp --dport 80  -j NFQUEUE --queue-num 0
	sudo iptables -A AXON_SINKHOLE -p tcp --dport 443 -j NFQUEUE --queue-num 0

rm-nftable:
	-sudo iptables -D OUTPUT -j AXON_SINKHOLE
	-sudo iptables -D FORWARD -j AXON_SINKHOLE
	-sudo iptables -F AXON_SINKHOLE
	-sudo iptables -X AXON_SINKHOLE

list-nftable:
	-sudo iptables -L AXON_SINKHOLE -n --line-numbers
	sudo nft list ruleset

build:
	cargo build --release

start:
	sudo ./target/release/sinkhole ledvance.ewyse.agency atun.com

