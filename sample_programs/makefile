all: opensocket mtu_sender mtu_receiver_bad mtu_receiver_good

opensocket: opensocket.c
	gcc -ggdb -o opensocket -static opensocket.c

mtu_sender: mtu_sender.c
	gcc -ggdb -o mtu_sender mtu_sender.c

mtu_receiver_bad: mtu_receiver_bad.c
	gcc -ggdb -o mtu_receiver_bad mtu_receiver_bad.c

mtu_receiver_good: mtu_receiver_good.c
	gcc -ggdb -o mtu_receiver_good mtu_receiver_good.c

clean:
	- rm mtu_sender
	- rm mtu_receiver_bad
	- rm opensocket
	- rm *.strace
