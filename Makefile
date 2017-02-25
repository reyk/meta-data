PROG=		meta-data
SRCS=		meta-data.c

BINDIR=		/usr/local/libexec

CFLAGS+=	-Wall -Wsign-compare -I/usr/local/include

#LDSTATIC=	${STATIC}

LDADD+=		-lkcgi -lkcgihtml -lz -L/usr/local/lib
DPADD+=		${LIBKCGI} ${LIBKCGIHTML} ${LIBZ}

all: README

README: ${.CURDIR}/meta-data.1
	mandoc -T ascii ${.CURDIR}/meta-data.1 | col -b > README

.include <bsd.prog.mk>
