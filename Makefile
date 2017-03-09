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

all: ${.CURDIR}/README.md

${.CURDIR}/README.md: ${.CURDIR}/meta-data.8
	mandoc -T markdown ${.CURDIR}/meta-data.8 > $@

.include <bsd.prog.mk>
