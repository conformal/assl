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
HDRS= assl.h

includes:
	@cd ${.CURDIR}; for i in ${HDRS}; do \
	cmp -s $$i ${DESTDIR}/usr/include/$$i || \
	${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i \
	${DESTDIR}/usr/include; done

.include <bsd.own.mk>
.include <bsd.lib.mk>
