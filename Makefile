ifneq ($(KERNELRELEASE),)
obj-m := netfilter_guard.o
netfilter_guard-y := src/netfilter_guard.o
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
