CONFIG_MODULE_SIG=n

obj-m += doot.o

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

install: default
	mkdir -p /usr/local/share/skeltal/
	install doot.png /usr/local/share/skeltal/doot.png
	install doot.jpg /usr/local/share/skeltal/doot.jpg
	install doot.svg /usr/local/share/skeltal/doot.svg
