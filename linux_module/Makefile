obj-m += vpoll.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	install -D vpoll.ko /lib/modules/$(shell uname -r)/misc/vpoll.ko
	depmod -a

