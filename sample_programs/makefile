all: opensocket mtu_sender mtu_receiver_bad mtu_receiver_good callread

opensocket: opensocket.c
	gcc -ggdb -o opensocket -static opensocket.c

mtu_sender: mtu_sender.c
	gcc -ggdb -o mtu_sender mtu_sender.c

mtu_receiver_bad: mtu_receiver_bad.c
	gcc -ggdb -o mtu_receiver_bad mtu_receiver_bad.c

mtu_receiver_good: mtu_receiver_good.c
	gcc -ggdb -o mtu_receiver_good -static mtu_receiver_good.c

callread: callread.c
	gcc -ggdb -o callread -static callread.c

clean:
	- rm mtu_sender
	- rm mtu_receiver_bad
	- rm mtu_receiver_good
	- rm opensocket
	- rm *.strace
	- rm callread
