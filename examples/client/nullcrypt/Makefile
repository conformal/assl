PROG=nullcrypt
NOMAN=

SRCS= nullcrypt.c
COPT+= -O2
DEBUG+= -g
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
CFLAGS+= -I${.CURDIR}/..
LDFLAGS+= -L/usr/local/lib -L ../../../../obj
LDADD+= -lssl -lcrypto -lassl

.include <bsd.prog.mk>
