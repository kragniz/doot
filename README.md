doot
====

Ensure your kernel thanks Mr. Skeltal for good calcium with this handy module.

Install
-------

Fetch doot dependencies (Red Hat flavoured):

    sudo dnf install kernel-headers kernel-devel

On debian based distros:

    sudo apt-get install linux-headers-generic

Make and install Mr. Skeltal:

    make
    sudo make install

To unleash Mr. Skeltal and begin dooting:

    sudo insmod doot.ko

To doot the last doot:

    sudo rmmod doot
