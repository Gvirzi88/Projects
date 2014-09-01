obj-m += xt_IPPORTS.o
obj-m += libxt_IPPORTS.o

EXTRA_CFLAGS = -O2

all:
	make -C /lib/modules/`uname -r`/build M=/home/user/xt_IPPORTS modules

clean:
	make -C /lib/modules/`uname -r`/build M=/home/user/xt_IPPORTS clean
