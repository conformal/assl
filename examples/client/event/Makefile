# $assl$

PROG=evclient
NOMAN=

SRCS= evclient.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
LDFLAGS+= -L/usr/local/lib -L ../../../../obj -lssl -lcrypto -lassl -levent

.include <bsd.prog.mk>
