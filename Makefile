PROG=		meta-data
SRCS=		meta-data.c

BINDIR=		/usr/local/libexec

CFLAGS+=	-Wall -I/usr/local/include
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-qual

#LDSTATIC=	${STATIC}

LDADD+=		-lkcgi -lkcgihtml -lz -L/usr/local/lib
DPADD+=		${LIBKCGI} ${LIBKCGIHTML} ${LIBZ}

MAN=		meta-data.8

all: README

README: ${.CURDIR}/meta-data.8
	mandoc -T ascii ${.CURDIR}/meta-data.8 | col -b > README

.include <bsd.prog.mk>
