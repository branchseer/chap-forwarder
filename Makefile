#CC	= gcc
COPTS	= -O2 -g
CFLAGS	= $(COPTS) -I. -I../.. -I../../../include -fPIC
LDFLAGS	= -shared
INSTALL	= install


DESTDIR = /usr
LIBDIR = $(DESTDIR)/lib/pppd/$(VERSION)

VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../../patchlevel.h)

PLUGINS := forwarder.so

all: $(PLUGINS)

%.so: %.o
	$(CC) $(CFLAGS) -o $@ -shared $^ $(LIBS)

install: all
	$(INSTALL) -d -m 755 $(LIBDIR)
	$(INSTALL) -c -m 755 $(PLUGINS) $(LIBDIR)

clean:
	rm -f *.o *.so

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<