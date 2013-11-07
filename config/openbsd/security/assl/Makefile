# $OpenBSD: Makefile,v 1.15 2011/07/04 16:39:33 dhill Exp $

COMMENT=		hide awful SSL API in a sane interface

DISTNAME=		assl-1.5.0
EPOCH=			1
CATEGORIES=		security devel
SHARED_LIBS=		assl 6.2

HOMEPAGE=		http://opensource.conformal.com/wiki/Assl
MASTER_SITES=		http://opensource.conformal.com/snapshots/assl/

MAINTAINER=		Conformal Systems LLC <info@conformal.com>

# ISC
PERMIT_PACKAGE_CDROM=	Yes

BUILD_DEPENDS =

NO_TEST=		Yes
EG_DIR=			${PREFIX}/share/examples/assl

FAKE_FLAGS=	MANDIR=${PREFIX}/man/man

do-configure:
	printf "major=${LIBassl_VERSION:R}\nminor=${LIBassl_VERSION:E}\n" \
	    > ${WRKSRC}/shlib_version

post-install:
	${INSTALL_DATA_DIR} ${EG_DIR}
	cd ${WRKSRC}/examples && \
		find . -type d \
			-exec ${INSTALL_DATA_DIR} ${EG_DIR}/{} \; && \
		find . ! -type d \
			-exec ${INSTALL_DATA} -m 644 {} ${EG_DIR}/{} \;

.include <bsd.port.mk>
