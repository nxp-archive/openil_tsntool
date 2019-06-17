#!/bin/bash
#
#Copyright 2019 NXP
#

if [ -z "$1" ]; then
    echo
    echo usage: $0 [network-interface]
    echo
    echo e.g. $0 eth0
    echo
    echo shows bits-per-second
    exit
fi

mkdir -p /tmp/static/

./txrxbytes.sh $1 &
./enetctscap -i $1 -c 0 -f &

sleep 1

ln -s /tmp/static/txrxpkts.json ./static/
ln -s /tmp/static/tsnframetstamp.json ./static/

echo "CONFIGPORT = \"$1\"" > config.py
python tsn.py
