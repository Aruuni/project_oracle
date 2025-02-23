obj-m += tcp_snap.o
# obj-m += kprobe_tcp_data_queue.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: modules

reload: remove modules insert

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

insert:
	sudo insmod tcp_snap.ko

remove:
	@if lsmod | grep -q "^tcp_snap "; then \
		sudo rmmod tcp_snap; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) cleana
