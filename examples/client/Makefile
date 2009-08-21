# $assl$

PROG=client
NOMAN=

SRCS= client.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../
LDFLAGS+= -L/usr/local/lib -L ../../../obj -lssl -lcrypto -lassl

.include <bsd.prog.mk>
