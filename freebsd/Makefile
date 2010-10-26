# $assl$

PREFIX?=/usr/local
BINDIR=${DESTDIR}${PREFIX}/bin
LIBDIR=${DESTDIR}${PREFIX}/lib

VPATH=..

.include <${.CURDIR}/../shlib_version>
VPATH=${.CURDIR}/..
SHLIB_MAJOR=${major}

#WANTLINT=
LIB= assl
SRCS= assl.c ssl_privsep.c
CFLAGS+= -Wall -Werror

# gcc4
CFLAGS+= -fdiagnostics-show-option -Wall -Werror
CFLAGS+= -ggdb3
CPPFLAGS+=-I${.CURDIR}

MAN= assl.3
MANDIR= ${PREFIX}/man/man
MLINKS+=assl.3 assl_initialize.3
MLINKS+=assl.3 assl_alloc_context.3
MLINKS+=assl.3 assl_set_cert_flags.3
MLINKS+=assl.3 assl_load_file_certs.3
MLINKS+=assl.3 assl_connect.3
MLINKS+=assl.3 assl_serve.3
MLINKS+=assl.3 assl_accept.3
MLINKS+=assl.3 assl_read.3
MLINKS+=assl.3 assl_write.3
MLINKS+=assl.3 assl_gets.3
MLINKS+=assl.3 assl_puts.3
MLINKS+=assl.3 assl_poll.3
MLINKS+=assl.3 assl_close.3
MLINKS+=assl.3 assl_fatalx.3
HDRS= assl.h

afterinstall:
	@cd ${.CURDIR}; for i in ${HDRS}; do \
	cmp -s ../$$i ${PREFIX}/include/$$i || \
	${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) ../$$i ${PREFIX}/include; \
	echo ${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) ../$$i ${PREFIX}/include; \
	done

.include <bsd.own.mk>
.include <bsd.lib.mk>
