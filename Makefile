KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default: reload

reload: remove modules insert

modules: oracle_module tcpsnap_module

oracle_module:
	$(MAKE) -C $(KDIR) M=$(PWD)/oracle modules

tcpsnap_module:
	$(MAKE) -C $(KDIR) M=$(PWD)/tcp_snap modules


oracle: remove_oracle oracle_module insert_oracle
tcpsnap: remove_tcpsnap tcpsnap_module insert_tcpsnap

insert: insert_oracle insert_tcpsnap

insert_oracle:
	sudo insmod $(PWD)/oracle/oracle.ko

insert_tcpsnap:
	sudo insmod $(PWD)/tcp_snap/tcp_snap.ko

remove: remove_oracle remove_tcpsnap

remove_oracle:
	@if lsmod | grep -q "^oracle "; then \
		sudo rmmod oracle; \
	fi

remove_tcpsnap:
	@if lsmod | grep -q "^tcp_snap "; then \
		sudo rmmod tcp_snap; \
	fi


clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/oracle clean
	$(MAKE) -C $(KDIR) M=$(PWD)/tcp_snap clean
