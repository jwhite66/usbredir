includes := -I$(PWD)/../usbredirparser/

obj-m += usbredir.o
usbredir-y := main.o sysfs.o hub.o device.o urb.o redir.o tx.o rx.o includes.o

modules:
	make ccflags-y="${includes} -DDEBUG" -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make ccflags-y="${includes}" -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
