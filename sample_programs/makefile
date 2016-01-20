all: opensocket mtu_receiver_good callread

opensocket: opensocket.c
	gcc -ggdb -o opensocket -static opensocket.c

mtu_receiver_good: mtu_receiver_good.c
	gcc -ggdb -o mtu_receiver_good -static mtu_receiver_good.c

callread: callread.c
	gcc -ggdb -o callread -static callread.c

callselect: callselect.c
	gcc -ggdb -o callselect -static callselect.c

clean:
	- rm mtu_receiver_good
	- rm opensocket
	- rm *.strace
	- rm callread
	- rm callselect
