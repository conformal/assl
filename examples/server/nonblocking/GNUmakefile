# $assl$

CFLAGS+= -O2 -Wall -ggdb -D_GNU_SOURCE -D_BSD_SOURCE -I ../../../
LDFLAGS+= -L/usr/local/lib -L ../../../ -lssl -lcrypto -lassl

CC=gcc

all: nbserver

nbserver: nbserver.c ../../../linux/strlcpy.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $+

clean:
	rm -rf nbserver *.o ../../../linux/*.o

.PHONY: all clean
