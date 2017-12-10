KSRC ?= /usr/src/linux

MODULES += HDLC_CISCO_ETH=m

INSTALL_MOD_OPTS  = INSTALL_MOD_PATH="$(DESTDIR)"
INSTALL_MOD_OPTS += INSTALL_MOD_STRIP=1

.PHONY: all clean install

all:
	make -C $(KSRC) M=$(CURDIR)/linux $(MODULES)

clean:
	make -C $(KSRC) M=$(CURDIR)/linux clean

install:
	make -C $(KSRC) M=$(CURDIR)/linux $(INSTALL_MOD_OPTS) modules_install
