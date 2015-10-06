all: mtu_sender mtu_receiver

mtu_sender: mtu_sender.c
	gcc -o mtu_sender mtu_sender.c

mtu_receiver: mtu_receiver.c
	gcc -o mtu_receiver mtu_receiver.c

clean:
	- rm mtu_sender
	- rm mtu_receiver
