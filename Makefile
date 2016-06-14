PREFIX=../staging_dir
export STAGING_DIR=../staging_dir
GCC=$(PREFIX)/toolchain/bin/mips-openwrt-linux-gcc
LD=$(PREFIX)/toolchain/bin/mips-openwrt-linux-ld
ALLFLAGS=-Wall -O2 -I$(PREFIX)/toolchain/include/ -I$(PREFIX)/target/usr/include/ -L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm 
GCCFLAGS=-Wall -O2 -I$(PREFIX)/toolchain/include/ -I$(PREFIX)/target/usr/include/
LDFLAGS=-L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm

TARGET=ips-ap

all: $(TARGET)

ips-ap: sniffer.o main.o http-client.o
	$(GCC) $(LDFLAGS) -o ips-ap sniffer.o main.o http-client.o

main.o : main.c sniffer.h
	$(GCC) $(GCCFLAGS) -c -o main.o main.c	
	
sniffer.o : sniffer.c sniffer.h http-client.h
	$(GCC) $(GCCFLAGS) -c -o sniffer.o sniffer.c

%.o : %.c %.h
	$(GCC) $(GCCFLAGS) -o $@ -c $<

clean:
	rm -f *.o
	rm -f rssi-display
	rm -f rssi-simple
	rm -f rssi-report
	rm -f openwrt-helloworld

backupclean:
	rm -f *~
