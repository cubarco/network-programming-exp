CC = gcc
CFLAGS += -Wall
LDFLAGS += -lev -lcrypto -llzo2

vpn: vpn.o crypto.o compress.o
vpn.o: vpn.c vpn.h common.h compress.h crypto.h
crypto.o: crypto.c crypto.h common.h
compress.o: compress.c compress.h common.h

.PHONY: all clean
all: vpn
clean:
	rm vpn *.o
