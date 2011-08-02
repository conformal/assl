# $assl$

PROG=fork_nbserver
NOMAN=

SRCS= fork_nbserver.c
COPT+= -O2
DEBUG+= -ggdb3 
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
LDFLAGS+= -L/usr/local/lib -L ../../../../obj -lssl -lcrypto -lassl -levent

.include <bsd.prog.mk>
