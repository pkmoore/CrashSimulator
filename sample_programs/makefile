
opensocket: opensocket.c
	gcc -ggdb -o opensocket -static opensocket.c
	strace -o opensocket.strace ./opensocket

mtu_sender: mtu_sender.c
	gcc -ggdb -o mtu_sender mtu_sender.c

mtu_receiver: mtu_receiver.c
	gcc -ggdb -o mtu_receiver mtu_receiver.c

all: mtu_sender mtu_receiver opensocket

clean:
	- rm mtu_sender
	- rm mtu_receiver
	- rm opensocket
