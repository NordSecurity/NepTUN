#!/bin/bash

wireguard-go wg0
wg set wg0 \
    listen-port 51820 \
    private-key <(echo MLBFYI9O69v8WdVodp4YucqnvW+onpD/R5kF/GE18F8=) \
    peer 7gr2QZyPpaIdlsPcZcQozgpjDdCkefZtxz12Dmpj/3Y= \
    allowed-ips 10.0.0.1/32 \
    endpoint 176.0.0.2:51820
ip address add dev wg0 10.0.0.2/24
ip link set up dev wg0

# /neptun/base/neptun-cli --disable-drop-privileges wg1
ip link add dev wg1 type wireguard
wg set wg1 \
    listen-port 51821 \
    private-key <(echo WAoFbPJ6QaXXltwLqBADFkMG6qLZuivSlkIUv2Sc3lY=) \
    peer HcDZRTIcI3Yok4XTwhAScKoNkb9MIZ2wyjS1oQvZnic= \
    allowed-ips 10.0.1.1/32 \
    endpoint 176.0.0.2:51821
ip address add dev wg1 10.0.1.2/24
ip link set up dev wg1

# /neptun/current/neptun-cli --disable-drop-privileges wg2
ip link add dev wg2 type wireguard
wg set wg2 \
    listen-port 51822 \
    private-key <(echo eNOePaXKpyN9IjNEDe1a4CzBAwdbLupbF5wfdCUjS18=) \
    peer zj6KZHkVw3ILScBGgUaYfuRkwhK6GgrIHmzfd4MPx1k= \
    allowed-ips 10.0.2.1/32 \
    endpoint 176.0.0.2:51822
ip address add dev wg2 10.0.2.2/24
ip link set up dev wg2

ip link add dev wg3 type wireguard
wg set wg3 \
    listen-port 51823 \
    private-key <(echo 4EMoCFW8H29xwDxAh1raNOQXOrppkYPJwlOmTd91un4=) \
    peer YisiciWrK2P7F8wG15A66v26+tmqEREsKfaSKfn4JHo= \
    allowed-ips 10.0.3.1/32 \
    endpoint 176.0.0.2:51823
ip address add dev wg3 10.0.3.2/24
ip link set up dev wg3

iperf3 -s > /dev/null &
touch /.iperf_ready
sleep infinity
