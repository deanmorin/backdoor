#!/bin/bash

if [ -z "$1" ]; then
    echo "$0 <ip>"
    exit 1
fi

# fix tr issues on OSX
if [ $(uname) == 'Darwin' ]; then
    export $LC_ALL=C
fi

shared_secret="this will be used for the port knocking hash"
random=$(cat /dev/urandom | tr -cd [:alnum:] | head -c 8)
knock_port=25068
port_to_open=00022
prehash="$shared_secret$random$port_to_open"
hashed=$(echo $prehash | sha1sum | awk '{print $1}')
msg="$hashed$random$port_to_open"
./client_util -e $msg

len=${#msg}
echo "Random: $random"
echo "Hash: $hashed"
echo "Length: $len"

#tcpid=$(./client_util -b $cmdlen)
#srcprt=$(./client_util)
#opts="-c 1 -2 -E /dev/stdin -d 100 -s $srcprt -p $knock_port -N $tcpid"
opts="-c 1 -2 -d 100 -p $knock_port"

hping3 $opts $1 --file temp_encrypted_message
rm temp_encrypted_message
