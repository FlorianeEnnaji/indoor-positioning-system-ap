PREFIX=../staging_dir
export STAGING_DIR=../staging_dir
GCC=$(PREFIX)/toolchain/bin/mips-openwrt-linux-gcc
LD=$(PREFIX)/toolchain/bin/mips-openwrt-linux-ld
#ALLFLAGS=-Wall -Werror -O2 -I$(PREFIX)/toolchain/include/ -I$(PREFIX)/target/usr/include/ -L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm -lcurl -lssl -lz -lcrypto -pthread
ALLFLAGS=-Wall -O2 -I$(PREFIX)/toolchain/include/ -I$(PREFIX)/target/usr/include/ -L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm -lssl -lz -lcrypto -pthread
GCCFLAGS=-Wall -O2 -I$(PREFIX)/toolchain/include/ -I$(PREFIX)/target/usr/include/
#LDFLAGS=-L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm -lcurl -pthread -lmicrohttpd -lpolarssl -lz #-lcrypto
LDFLAGS=-L$(PREFIX)/toolchain/lib/ -L$(PREFIX)/target/usr/lib/ -lpcap -lm -pthread -lz #-lcrypto

# oWRT-HelloWorld: openwrt-helloworld.c
# 	$(GCC) $(ALLFLAGS) openwrt-helloworld.c -o openwrt-helloworld

#TARGET=rssi-display
TARGET=main

all: $(TARGET)

main: sniffer.o main.o http-client.o packet-ieee80211-radiotap-iter.o
	$(GCC) $(LDFLAGS) -o main sniffer.o main.o http-client.o packet-ieee80211-radiotap-iter.o

main.o : main.c sniffer.h http-client.h
	$(GCC) $(GCCFLAGS) -c -o main.o main.c

rssi-display.o: rssi-display.c rssi_list.h
	$(GCC) $(GCCFLAGS) -c -o rssi-display.o rssi-display.c

rssi-simple.o: rssi-simple.c headers.h
	$(GCC) $(GCCFLAGS) -c -o rssi-simple.o rssi-simple.c

%.o : %.c %.h
	$(GCC) $(GCCFLAGS) -o $@ -c $<

rssi-display: rssi-display.o rssi_list.o http-server.o pcap-thread.o init-ap.o
	$(GCC) $(LDFLAGS) -o rssi-display rssi-display.o rssi_list.o http-server.o pcap-thread.o init-ap.o

rssi-simple: rssi-simple.o pcap-simple.o iface-mgt.o
	$(GCC) $(LDFLAGS) -o rssi-simple rssi-simple.o pcap-simple.o iface-mgt.o

clean:
	rm -f *.o
	rm -f rssi-display
	rm -f rssi-simple
	rm -f rssi-report
	rm -f openwrt-helloworld

backupclean:
	rm -f *~
