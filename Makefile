PROG=		meta-data
SRCS=		meta-data.c

BINDIR=		/usr/local/libexec

CFLAGS+=	-Wall -Wsign-compare -I/usr/local/include

#LDSTATIC=	${STATIC}

LDADD+=		-lkcgi -lkcgihtml -lz -L/usr/local/lib
DPADD+=		${LIBKCGI} ${LIBKCGIHTML} ${LIBZ}

NOMAN=		yes

.include <bsd.prog.mk>
