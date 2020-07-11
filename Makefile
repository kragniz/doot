obj-m += doot.o


default:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: default
	mkdir -p /usr/local/share/skeltal/
	install doot.png /usr/local/share/skeltal/doot.png
	install doot.jpg /usr/local/share/skeltal/doot.jpg
	install doot.svg /usr/local/share/skeltal/doot.svg
	install doot_black.gif /usr/local/share/skeltal/doot_black.gif
