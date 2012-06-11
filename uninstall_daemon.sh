#!/bin/bash

if [ "$(whoami)" != "root" ]; then
    echo "> This script must be run as root." 
    exit
fi

chkconfig --del udevd
rm /etc/init.d/udevd
