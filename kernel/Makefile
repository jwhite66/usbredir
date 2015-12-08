includes := -I$(PWD)/../usbredirparser/

MODULE_VERSION ?= $(shell uname -r)
install_target := $(DESTDIR)/lib/modules/$(MODULE_VERSION)/kernel/drivers/usb/misc/

INSTALL_PROGRAM ?= install

obj-m += usbredir.o
usbredir-y := main.o sysfs.o hub.o device.o urb.o redir.o tx.o rx.o includes.o

usbredir.ko:
	make ccflags-y="${includes} -DDEBUG" -C /lib/modules/$(MODULE_VERSION)/build/ M=$(PWD) modules

clean:
	make ccflags-y="${includes}" -C /lib/modules/$(MODULE_VERSION)/build/ M=$(PWD) clean

install: usbredir.ko
	mkdir -p $(install_target)
	$(INSTALL_PROGRAM) usbredir.ko $(install_target)

all: usbredir.ko
