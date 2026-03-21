sudo iptables -I OUTPUT  -p tcp --dport 80  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT  -p tcp --dport 443 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT  -p udp --dport 53  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT  -p udp --dport 443 -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p tcp --dport 80  -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p udp --dport 53  -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -p udp --dport 443 -j NFQUEUE --queue-num 0


sudo ./target/release/sinkhole ledvance.ewyse.agency atun.com




curl atun.com
wget atun.com

curl https://atun.com

curl http://atun.com

curl http://atun.com

ping ledvance.ewyse.agency 
ping polyglotte-institute.eu 




sudo iptables -D OUTPUT  -p tcp --dport 80  -j NFQUEUE --queue-num 0