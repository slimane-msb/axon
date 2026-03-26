#!/bin/bash

# Term1
sudo ./axond

# Term3
cd sinkhole
make add-nftable
make start 

# Term 2
sudo ./axon add-iface wlp8s0

ping 185.99.197.3
sudo ./axon add-ip wlp8s0 185.99.197.3
ping 185.99.197.3
ping 103.224.182.246
sudo ./axon remove-ip wlp8s0 185.99.197.3
ping 185.99.197.3


curl fox.com
sudo ./axon add-web wlp8s0 fox.com
curl fox.com
curl cat.com

sudo ./axon remove-web wlp8s0 fox.com
curl fox.com

curl ledvance.ewyse.agency
sudo ./axon add-web wlp8s0 polyglotte-institute.eu
curl polyglotte-institute.eu
sudo ./axon remove-web wlp8s0 ledvance.ewyse.agency

sudo ./axon status wlp8s0