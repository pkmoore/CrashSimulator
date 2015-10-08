all: mtu_sender mtu_receiver opensocket

open_socket: opensocket.c
	gcc -o opensocket -static opensocket.c

mtu_sender: mtu_sender.c
	gcc -o mtu_sender mtu_sender.c

mtu_receiver: mtu_receiver.c
	gcc -o mtu_receiver mtu_receiver.c

clean:
	- rm mtu_sender
	- rm mtu_receiver
