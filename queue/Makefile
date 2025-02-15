# Makefile for building and automatically loading the oracle qdisc module

obj-m += oracle.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: modules insmod

reload: clean rmmod default

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

insmod:
	sudo insmod oracle.ko

rmmod:
	sudo rmmod oracle

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
