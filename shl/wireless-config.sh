#!/bin/sh
if [ ! $1 ]; then
    echo -e "Usage: $0 INTERFACE (the 802.11 interface from iwconfig command)"
    exit 1
fi
INTERFACE=$1

sudo ifconfig $INTERFACE down
sudo iwconfig $INTERFACE mode monitor
sudo ifconfig $INTERFACE mtu 2304
sudo ifconfig $INTERFACE up
sudo iwconfig $INTERFACE channel 1
sudo iwconfig $INTERFACE