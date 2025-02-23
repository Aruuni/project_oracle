obj-m += oracle.o
# obj-m += kprobe_tcp_data_queue.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: modules

reload: remove modules insert

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

insert:
	sudo insmod oracle.ko

remove:
	@if lsmod | grep -q "^oracle "; then \
		sudo rmmod oracle; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) cleana
