$ git clone http://github.com/deanmorin/backdoor.git
$ git checkout assign3

$ ./install_daemon      // not necessary for demoing
$ make debug
$ sudo ./readlog

$ (server)
$ ./sendcmd.sh

$ git clone http://github.com/deanmorin/covert.git
$ git checkout assign3
$ make debug
$ sudo ./covert -s
#################
knock
$ make client_util
$ sudo ./knock <ip> 



$ ./uninstall_daemon
