CONFIG_MODULE_SIG=n

obj-m += doot.o

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
