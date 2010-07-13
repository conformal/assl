# $assl$

#.PATH:		${.CURDIR}/..

#WANTLINT=
LIB= assl
SRCS= assl.c
DEBUG+= -ggdb3 
.if defined(${COMPILER_VERSION})  &&  ${COMPILER_VERSION:L} == "gcc4"

CFLAGS+= -fdiagnostics-show-option -Wall -Werror
.else
CFLAGS+= -Wall -Werror
.endif
MAN= assl.3
MLINKS+=assl.3 assl_initialize.3
MLINKS+=assl.3 assl_alloc_context.3
MLINKS+=assl.3 assl_set_cert_flags.3
MLINKS+=assl.3 assl_load_file_certs.3
MLINKS+=assl.3 assl_connect.3
MLINKS+=assl.3 assl_serve.3
MLINKS+=assl.3 assl_accept.3
MLINKS+=assl.3 ssl_read.3
MLINKS+=assl.3 assl_write.3
MLINKS+=assl.3 assl_gets.3
MLINKS+=assl.3 assl_puts.3
MLINKS+=assl.3 assl_poll.3
MLINKS+=assl.3 assl_close.3
MLINKS+=assl.3 assl_fatalx.3
HDRS= assl.h

includes:
	@cd ${.CURDIR}; for i in ${HDRS}; do \
	cmp -s $$i ${DESTDIR}/usr/include/$$i || \
	${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i \
	${DESTDIR}/usr/include; done

.include <bsd.own.mk>
.include <bsd.lib.mk>
