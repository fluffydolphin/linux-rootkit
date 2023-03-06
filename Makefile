obj-m += rootkit.o
ccflags-y := -I/usr/include/x86_64-linux-gnu

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean