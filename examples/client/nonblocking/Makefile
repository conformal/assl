PROG=nbclient
NOMAN=

SRCS= nbclient.c
COPT+= -O2
DEBUG+= -g
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
CFLAGS+= -I${.CURDIR}/..
LDADD+= -L/usr/local/lib -L ../../../../obj -lssl -lcrypto -lassl

.include <bsd.prog.mk>
