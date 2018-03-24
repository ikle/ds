obj-$(HDLC_CISCO_ETH)	+= hdlc_cisco_eth.o
obj-$(HDLC_TUN)		+= hdlc_tun.o hdlc_lib.o

obj-$(PDS)		+= pds.o
pds-y			:= pds-module.o pds-net.o pds-tdm.o
ccflags-y		+= -I$(DAHDI)/include

#CFLAGS_pds.o		+= -I$(DAHDI)/include
