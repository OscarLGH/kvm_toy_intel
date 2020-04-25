kvm-toy-intel-y += vmx.o guest.o

obj-m := kvm-toy-intel.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
