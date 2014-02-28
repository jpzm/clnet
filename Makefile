CC = cc
CFLAGS = -ggdb -Wall
LD = "../../"

default: all

all:
	cd code; ${CC} ${CFLAGS} -I${LD} -shared -fPIC -c *.c
	cd test; ${CC} ${CFLAGS} -I${LD} isn.c -o isn \
		../../clads/code/clads.o \
		../code/clnet.o -lpcap -lnet -lm

clean:
	cd code; rm -rf *.o
	cd test; rm -rf \
		isn
