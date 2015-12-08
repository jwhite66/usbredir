includes := -I$(PWD)/../usbredirparser/

MODULE_VERSION ?= $(shell uname -r)
modules_target := $(DESTDIR)/lib/modules/$(MODULE_VERSION)/kernel/drivers/usb/misc/
sysconfig_target := $(DESTDIR)/etc/sysconfig/modules/

INSTALL_PROGRAM ?= install

obj-m += usbredir.o
usbredir-y := main.o sysfs.o hub.o device.o urb.o redir.o tx.o rx.o includes.o

usbredir.ko:
	make ccflags-y="${includes} -DDEBUG" -C /lib/modules/$(MODULE_VERSION)/build/ M=$(PWD) modules

clean:
	make ccflags-y="${includes}" -C /lib/modules/$(MODULE_VERSION)/build/ M=$(PWD) clean

install: usbredir.ko usbredir.modules
	mkdir -p $(modules_target)
	$(INSTALL_PROGRAM) usbredir.ko $(modules_target)
	mkdir -p $(sysconfig_target)
	$(INSTALL_PROGRAM) usbredir.modules $(sysconfig_target)

all: usbredir.ko
