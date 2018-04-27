obj-m += namesetmodule.o
namesetmodule-objs := resolv.o local_ns_parser.o test.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
