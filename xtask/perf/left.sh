#!/bin/bash

wireguard-go wg0
wg set wg0 \
    listen-port 51820 \
    private-key <(echo AH7jKt6M0RS21MkRG+URrfgmwvJqdhVvqtKeF4WR+E8=) \
    peer mqrc8+LD+6zvMeCtyCcIBPEYuXT74lq1Hros0Np8ZgA= \
    allowed-ips 10.0.0.2/32 \
    endpoint 176.0.0.3:51820
ip address add dev wg0 10.0.0.1/24
ip link set up dev wg0

/neptun/base/neptun-cli --disable-drop-privileges wg1
wg set wg1 \
    listen-port 51821 \
    private-key <(echo sKZoT3qgxDm1bWny+1ttoi00qS2KXvo1L4Zb265wr3c=) \
    peer CMWokCGH+YPN7CL2C2aAkDlnhw1blH0tKPOnEOgzrxM= \
    allowed-ips 10.0.1.2/32 \
    endpoint 176.0.0.3:51821
ip address add dev wg1 10.0.1.1/24
ip link set up dev wg1

/neptun/current/neptun-cli --disable-drop-privileges wg2
wg set wg2 \
    listen-port 51822 \
    private-key <(echo 0Fn5JWI1QGDiaVYLDBSLklIEBUujfpX1oH/UGI2D62k=) \
    peer fqrU1Wk8nuyy6phf8IUDwcKK1ElslFYDyteANr2hlgM= \
    allowed-ips 10.0.2.2/32 \
    endpoint 176.0.0.3:51822
ip address add dev wg2 10.0.2.1/24
ip link set up dev wg2

# echo
# echo "Raw network:"
# iperf3 -i 10 -t  10 --bidir -c 176.0.0.3

# echo
# echo "Wireguard-go:"
# iperf3 -i 60 -t 120 --bidir -c 10.0.0.2

echo
echo "Base NepTUN: 40M"
iperf3 -i 60 -t 120 -u -b 40M -c 10.0.1.2
echo "Base NepTUN: 100M"
iperf3 -i 60 -t 120 -u -b 100M -c 10.0.1.2
echo "Base NepTUN: 200M"
iperf3 -i 60 -t 120 -u -b 200M -c 10.0.1.2
echo "Base NepTUN: 500M"
iperf3 -i 60 -t 120 -u -b 500M -c 10.0.1.2
echo "Base NepTUN: 1000M"
iperf3 -i 60 -t 120 -u -b 1000M -c 10.0.1.2
echo "Base NepTUN: 1500M"
iperf3 -i 60 -t 120 -u -b 1500M -c 10.0.1.2
echo "Base NepTUN: 1800M"
iperf3 -i 60 -t 120 -u -b 1800M -c 10.0.1.2
echo "Base NepTUN: 2000M"
iperf3 -i 60 -t 120 -u -b 2000M -c 10.0.1.2
echo "Base NepTUN: 2200M"
iperf3 -i 60 -t 120 -u -b 2200M -c 10.0.1.2
echo "Base NepTUN: 2300M"
iperf3 -i 60 -t 120 -u -b 2300M -c 10.0.1.2
echo "Base NepTUN: 2400M"
iperf3 -i 60 -t 120 -u -b 2400M -c 10.0.1.2
echo "Base NepTUN: 2700M"
iperf3 -i 60 -t 120 -u -b 2700M -c 10.0.1.2
echo "Base NepTUN: 3000M"
iperf3 -i 60 -t 120 -u -b 3000M -c 10.0.1.2
echo "Base NepTUN: 3500M"
iperf3 -i 60 -t 120 -u -b 3500M -c 10.0.1.2
echo "Base NepTUN: 4000M"
iperf3 -i 60 -t 120 -u -b 4000M -c 10.0.1.2
echo "Base NepTUN: 4500M"
iperf3 -i 60 -t 120 -u -b 4500M -c 10.0.1.2
echo "Base NepTUN: 5000M"
iperf3 -i 60 -t 120 -u -b 5000M -c 10.0.1.2
echo "Base NepTUN: 5500M"
iperf3 -i 60 -t 120 -u -b 5500M -c 10.0.1.2

echo
echo "Current NepTUN: 40M"
iperf3 -i 60 -t 120 -u -b 40M -c 10.0.2.2
echo "Current NepTUN: 100M"
iperf3 -i 60 -t 120 -u -b 100M -c 10.0.2.2
echo "Current NepTUN: 200M"
iperf3 -i 60 -t 120 -u -b 200M -c 10.0.2.2
echo "Current NepTUN: 500M"
iperf3 -i 60 -t 120 -u -b 500M -c 10.0.2.2
echo "Current NepTUN: 1000M"
iperf3 -i 60 -t 120 -u -b 1000M -c 10.0.2.2
echo "Current NepTUN: 1500M"
iperf3 -i 60 -t 120 -u -b 1500M -c 10.0.2.2
echo "Current NepTUN: 1800M"
iperf3 -i 60 -t 120 -u -b 1800M -c 10.0.2.2
echo "Current NepTUN: 2000M"
iperf3 -i 60 -t 120 -u -b 2000M -c 10.0.2.2
echo "Current NepTUN: 2200M"
iperf3 -i 60 -t 120 -u -b 2200M -c 10.0.2.2
echo "Current NepTUN: 2300M"
iperf3 -i 60 -t 120 -u -b 2300M -c 10.0.2.2
echo "Current NepTUN: 2400M"
iperf3 -i 60 -t 120 -u -b 2400M -c 10.0.2.2
echo "Current NepTUN: 2700M"
iperf3 -i 60 -t 120 -u -b 2700M -c 10.0.2.2
echo "Current NepTUN: 3000M"
iperf3 -i 60 -t 120 -u -b 3000M -c 10.0.2.2
echo "Current NepTUN: 3500M"
iperf3 -i 60 -t 120 -u -b 3500M -c 10.0.2.2
echo "Current NepTUN: 4000M"
iperf3 -i 60 -t 120 -u -b 4000M -c 10.0.2.2
echo "Current NepTUN: 4500M"
iperf3 -i 60 -t 120 -u -b 4500M -c 10.0.2.2
echo "Current NepTUN: 5000M"
iperf3 -i 60 -t 120 -u -b 5000M -c 10.0.2.2
echo "Current NepTUN: 5500M"
iperf3 -i 60 -t 120 -u -b 5500M -c 10.0.2.2

