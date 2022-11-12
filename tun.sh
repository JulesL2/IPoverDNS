#!bin/bash
openvpn --mktun --dev tun1
ip link set tun1 up
ip addr add 10.0.0.1/24 dev tun1
