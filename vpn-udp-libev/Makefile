CC = gcc
CFLAGS += -Wall
LDFLAGS += -lev

vpn-udp-libev: vpn-udp-libev.o
vpn-udp-libev.o: vpn-udp-libev.c

.PHONY: all clean
all: vpn-udp-libev
clean:
	rm vpn-udp-libev *.o
