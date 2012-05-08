PROG=nullcrypt
NOMAN=

SRCS= nullcrypt.c
COPT+= -O2
DEBUG+= -g
CFLAGS+= -Wall -Werror
CFLAGS+= -I/usr/local/include -I ../../../../
LDFLAGS+= -L/usr/local/lib -L ../../../../obj -lssl -lcrypto -lassl -levent_core

.include <bsd.prog.mk>
