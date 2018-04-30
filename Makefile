obj-m += xt_nameset.o
xt_nameset-objs := resolv.o local_ns_parser.o xt_nameset_main.o
CFLAGS_xt_nameset_main.o := -DDEBUG -Wall

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
