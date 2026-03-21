echo '{"cmd":"add-iface","iface":"wlp8s0","val":""}' | nc -U /tmp/blockd.sock
echo '{"cmd":"add-web","iface":"wlp8s0","val":"atun.com"}' | nc -U /tmp/blockd.sock

# add a web directly to ctl at runtime (bypasses daemon)
cd axon/sinkhole && make add WEB=atun.com

# add an IP via daemon (L3/XDP path)
echo '{"cmd":"add-ip","iface":"wlp8s0","val":"1.2.3.4"}' | nc -U /tmp/blockd.sock

# test blocking
curl -v https://atun.com         # should be dropped
curl -v https://google.com       # should pass

# remove
cd axon/sinkhole && make remove WEB=atun.com