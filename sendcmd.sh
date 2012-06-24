#!/bin/bash

if [ -z "$2" ]; then
    echo "$0 <ip> <command>"
    exit 1
fi

cmdlen=$(expr length "$2")
len=$(expr $cmdlen + 4)
echo $len
tcpid=$(./client_util -b $cmdlen)
srcprt=$(./client_util)
dstprt=34249
opts="-c 1 -2 -d 100 -s $srcprt -p $dstprt -N $tcpid"
./client_util -e "$2"

cat temp_encrypted_message | wc -c
hping3 $opts $1 --file temp_encrypted_message
rm temp_encrypted_message
