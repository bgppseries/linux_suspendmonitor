KERDIR = /lib/modules/$(shell uname -r)/build
obj-m += suspend_monitor.o

build:
	make -C $(KERDIR) M=$(CURDIR) modules

clean:
	make -C $(KERDIR) M=$(CURDIR) clean 
