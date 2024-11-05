#!/bin/bash
# cd /app/router-rs
# cargo run

# cd /app/src/
# make
# ./main

# Chapter 3
# cd /app/src/ch3
# make
# ./pcap eth0

# Chapter 4
# cd /app/src/ch4
# make
# ./bridge

# Chapter 5
cd /app/src/ch5
/sbin/sysctl net.ipv4.ip_forward # make sure that the value is 1
make
./router

bash -c "/bin/bash"