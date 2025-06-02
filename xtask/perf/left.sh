#!/bin/bash

######################################################
# This script is used to setup testing environment   #
# for performance measurements. The keys here are    #
# for testing purposes only and must never be used   #
# in any real deployments                            #
######################################################

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

/neptun/base/neptun-cli --disable-drop-privileges wg2
wg set wg2 \
    listen-port 51822 \
    private-key <(echo 0Fn5JWI1QGDiaVYLDBSLklIEBUujfpX1oH/UGI2D62k=) \
    peer fqrU1Wk8nuyy6phf8IUDwcKK1ElslFYDyteANr2hlgM= \
    allowed-ips 10.0.2.2/32 \
    endpoint 176.0.0.3:51822
ip address add dev wg2 10.0.2.1/24
ip link set up dev wg2

echo
echo "Raw network:"
iperf3 -i 10 -t  10 --bidir -c 176.0.0.3

echo
echo "Wireguard-go:"
iperf3 -i 10 -t 30 --bidir -c 10.0.0.2

echo
echo "TCP bidirectional tests"

echo
echo "Base NepTUN:"
iperf3 -i 10 -t 30 -c 10.0.1.2

echo
echo "Current NepTUN:"
iperf3 -i 10 -t 30 -c 10.0.2.2

sleep 1
echo
echo "UDP unidirectional tests"

bitrates=(1500M)

for bitrate in "${bitrates[@]}"
do
    echo
    echo "Running test for bitrate: $bitrate"
    # Base NepTUN
    base_cmd=$(iperf3 -i 10 -t 30 -u -b "$bitrate" -c 10.0.1.2 | awk '/receiver/')
    base_output="$base_cmd"
    base_total_datagrams=$(echo "$base_output" | awk '{print $11}' | awk -F '/' '{print $2}')
    base_lost_datagrams=$(echo "$base_output" | awk '{print $11}' | awk -F '/' '{print $1}')
    base_lost_percentage=$(echo "$base_output" | awk '{print $12}')
    base_bitrate=$(echo "$base_output" | awk '{print $7 " " $8}')

    sleep 2
    # Current NepTUN
    current_cmd=$(iperf3 -i 10 -t 30 -u -b "$bitrate" -c 10.0.2.2 | awk '/receiver/')
    current_output="$current_cmd"
    ip -s link show dev wg1 | awk 'NR==6 {print "Base tunnel - success:", $2, "drops:", $4}'
    ip -s link show dev wg2 | awk 'NR==6 {print "Current tunnel - success:", $2, "drops:", $4}'
    current_total_datagrams=$(echo "$current_output" |  awk '{print $11}' | awk -F '/' '{print $2}')
    current_lost_datagrams=$(echo "$current_output" | awk '{print $11}' | awk -F '/' '{print $1}')
    current_lost_percentage=$(echo "$current_output" | awk '{print $12}')
    current_bitrate=$(echo "$current_output" | awk '{print $7 " " $8}')

    # Print results
    echo "Connection       | Total Datagrams | Lost   |  (%) | Received Bitrate"
    echo "Base NepTUN      | $base_total_datagrams         | $base_lost_datagrams | $base_lost_percentage  | $base_bitrate "
    echo "Current NepTUN   | $current_total_datagrams         | $current_lost_datagrams |  $current_lost_percentage | $current_bitrate "

    value=$(echo "$current_lost_percentage" | awk '{gsub(/[^0-9.]/, ""); print $0}')
    if [[ $value -gt 10 ]]; then
        exit 0
    fi
    sleep 2
done
