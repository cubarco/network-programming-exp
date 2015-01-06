CC = gcc
CFLAGS += -Wall
LDFLAGS += -lev

vpn: vpn.o
vpn.o: vpn.c

.PHONY: all clean
all: vpn
clean:
	rm vpn *.o
