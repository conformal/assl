# $assl$

CFLAGS+= -O2 -Wall -ggdb -D_GNU_SOURCE -D_BSD_SOURCE -I.
LDFLAGS+=
LDADD+= -lssl

PREFIX?= /usr/local
LIBDIR?= $(PREFIX)/lib
MANDIR?= $(PREFIX)/share/man

CC= gcc

LVERS= $(shell . shlib_version; echo $$major.$$minor)

all: libassl.so.$(LVERS)

%.so: %.c
	$(CC) $(CFLAGS) -c -fpic -DPIC $+ -o $@

libassl.so.$(LVERS): assl.so
	$(CC) -shared -fpic -o libassl.so.$(LVERS) assl.so $(LDADD)
	ln -sf libassl.so.$(LVERS) libassl.so

install: all
	install -Dm 644 assl.3 $(DESTDIR)$(MANDIR)/man3/assl.3
	install -Dm 755 libassl.so.$(LVERS) $(DESTDIR)$(LIBDIR)
	ln -sf $(DESTDIR)$(LIBDIR)/libassl.so.$(LVERS) $(DESTDIR)$(LIBDIR)/libassl.so

clean:
	rm -f assl.so libassl.so.$(LVERS) libassl.so *.o linux/*.o

.PHONY: all install clean
