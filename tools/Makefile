TARGETS = pds-emu

CFLAGS  += -Wall -O6

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

pds-emu: CFLAGS  += -I$(CURDIR)/../linux
