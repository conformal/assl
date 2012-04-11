SYSTEM != uname -s
.if exists(${.CURDIR}/config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/config/Makefile.$(SYSTEM:L)"
.endif

LOCALBASE?=/usr/local
LIBDIR?=${LOCALBASE}/lib
INCDIR?=${LOCALBASE}/include

#WANTLINT=
LIB= assl
SRCS= assl.c assl_socket.c ssl_privsep.c
HDRS= assl.h assl_socket.h
MAN= assl.3
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

BUILDVERSION != sh "${.CURDIR}/buildver.sh"

DEBUG+= -g
CFLAGS+= -Wall -Werror
CFLAGS+= -I${.CURDIR} -I${INCDIR}
CFLAGS+= -DASSL_NO_FANCY_ERRORS
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
.endif


CLEANFILES+= assl.cat3

afterinstall:
	@cd ${.CURDIR}; for i in ${HDRS}; do \
	cmp -s $$i ${DESTDIR}${LOCALBASE}/include/$$i || \
	${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i ${DESTDIR}${LOCALBASE}/include; \
	echo ${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i ${DESTDIR}${LOCALBASE}/include; \
	done

uninstall:
	@for i in $(HDRS); do \
	echo rm -f ${INCDIR}/$$i ;\
	rm -f ${INCDIR}/$$i; \
	done

	@for i in $(_LIBS); do \
	echo rm -f ${LIBDIR}/$$i ;\
	rm -f ${LIBDIR}/$$i; \
	done

.include <bsd.own.mk>
.include <bsd.lib.mk>
