PROG=nbserver
NOMAN=

SRCS= nbserver.c
COPT+= -O2
DEBUG+= -g
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
LDFLAGS+= -L/usr/local/lib -L ../../../../obj -lssl -lcrypto -lassl

.include <bsd.prog.mk>
