# $assl$

#.PATH:		${.CURDIR}/..

WANTLINT=
LIB=	assl
SRCS=	assl.c
DEBUG+= -ggdb3 
CFLAGS+= -Wall
MAN=	assl.3

.include <bsd.own.mk>
.include <bsd.lib.mk>
