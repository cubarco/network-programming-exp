CC = gcc
CFLAGS += -Wall
LDFLAGS += -lev -lcrypto

vpn: vpn.o crypto.o
vpn.o: vpn.c crypto.c

.PHONY: all clean
all: vpn
clean:
	rm vpn *.o
