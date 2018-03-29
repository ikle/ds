KSRC ?= /usr/src/linux

DAHDI ?= $(HOME)/tmp/dahdi-linux-2.6.1+dfsg2

MODULES += HDLC_CISCO_ETH=m
MODULES += HDLC_TUN=m

MODULES += DAHDI=$(DAHDI)
MODULES += KBUILD_EXTRA_SYMBOLS=$(CURDIR)/linux/Module.symvers-dahdi
MODULES += PDS=m

INSTALL_MOD_OPTS  = INSTALL_MOD_PATH="$(DESTDIR)"
INSTALL_MOD_OPTS += INSTALL_MOD_STRIP=1

.PHONY: all clean install

all:
	make -C $(KSRC) M=$(CURDIR)/linux $(MODULES)
	make -C tools

clean:
	make -C $(KSRC) M=$(CURDIR)/linux clean
	make -C tools clean

install:
	make -C $(KSRC) M=$(CURDIR)/linux $(INSTALL_MOD_OPTS) modules_install
	make -C tools install
