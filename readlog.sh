#!/bin/bash

if [ "$(whoami)" != "root" ]; then
    echo "> This script must be run as root." 
    exit
fi

tail -n 50 -f /var/log/messages | grep --line-buffered udevd | sed -e 's;.*\[[0-9]\{1,5\}\]: ;;g' -e 's;^0x[0-9]\{4\}:  ;\t&;'
