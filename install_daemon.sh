#!/bin/bash

if [ "$(whoami)" != "root" ]; then
    echo "> This script must be run as root." 
    exit
fi

dir=$(dirname $(readlink -f $0))

echo "\
#!/bin/bash
# chkconfig: 35 99 1
# description: event managing daemon

case "\$1" in
    'start')
        $dir/udevd
        ;;
    'stop')
        pkill $dir/udevd
        ;;
    'restart')
        pkill -HUP $dir/udevd
        ;;
esac" > /etc/init.d/udevd

chown root:root /etc/init.d/udevd
chkconfig --add udevd
