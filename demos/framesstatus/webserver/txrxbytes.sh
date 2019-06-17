#!/bin/bash
#
#Copyright 2019 NXP
#

INTERVAL="1" # update interval in seconds

if [ -z "$1" ]; then
    echo
    echo usage: $0 [network-interface]
    echo
    echo e.g. $0 eth0
    echo
    echo shows bits-per-second
    exit
fi

IF=$1
JSON_FMT='{\n "TIME":"%s",\n "TX":"%s",\n "RX":"%s"\n}\n'

while true
do
    R1=`cat /sys/class/net/$1/statistics/rx_bytes`
    T1=`cat /sys/class/net/$1/statistics/tx_bytes`
    sleep $INTERVAL
    R2=`cat /sys/class/net/$1/statistics/rx_bytes`
    T2=`cat /sys/class/net/$1/statistics/tx_bytes`
    #TXPPS=`expr $T2 - $T1`
    #RXPPS=`expr $R2 - $R1`
    TXPPS=$[$[ $T2 - $T1 ] * 8]
    RXPPS=$[$[ $R2 - $R1 ] * 8]
    TIME=`date +%s`
    #echo "TX $1: $TXPPS pkts/s RX $1: $RXPPS pkts/s"
    printf "$JSON_FMT" "$TIME" "$TXPPS" "$RXPPS" > /tmp/static/txrxpkts.json
done

