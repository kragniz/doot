doot
====

Ensure your kernel thanks Mr. Skeltal for good calcium with this handy module.
![doot](doot.png)

Context
-------
This is a fork of [kragniz/doot](https://github.com/kragniz/doot).
When I stumbled upon it, I wanted to get it to run again but given that
the original doot module was written over 5 years ago, it would require
significant changes. I don't want to overwrite their code because it's
cool to compare what you can/can't write in modules between vastly different
kernel versions. All credit goes to [kragniz](https://github.com/kragniz)
for the original idea :^)

Support
-------
I'm pretty sure this will only work on **x86-64** architectures, based off of [this](https://lwn.net/Articles/750536/)
patch. Additionally, I've only tested on the following distributions:
- **Debian 10.20 (Buster), kernel version 4.19**
- **Ubuntu 20.04 (Focal), kernel version 5.4**

Install
-------

Fetch doot dependencies (Debian):

    sudo apt install linux-headers-$(uname -r)

On Ubuntu based distros:

    sudo apt-get install linux-headers-$(uname -r)

Make and install Mr. Skeltal:

    make
    sudo make install

To unleash Mr. Skeltal and begin dooting:

    sudo insmod doot.ko

To doot the last doot:

    sudo rmmod doot
