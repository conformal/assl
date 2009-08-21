# $assl$

#.PATH:		${.CURDIR}/..

WANTLINT=
LIB=	assl
SRCS=	assl.c
DEBUG+= -ggdb3 
CFLAGS+= -Wall
NOMAN=

.include <bsd.own.mk>
.include <bsd.lib.mk>
