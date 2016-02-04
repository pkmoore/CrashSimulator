all: opensocket mtu_receiver_good callread callselect callstat64 callllseek callgetcwd calluname callgetrlimit

opensocket: opensocket.c
	gcc -ggdb -o opensocket -static opensocket.c

mtu_receiver_good: mtu_receiver_good.c
	gcc -ggdb -o mtu_receiver_good -static mtu_receiver_good.c

callgetrlimit: callgetrlimit.c
	gcc -ggdb -o callgetrlimit -static callgetrlimit.c

callllseek: callllseek.c
	gcc -ggdb -o callllseek -static callllseek.c

callread: callread.c
	gcc -ggdb -o callread -static callread.c

callselect: callselect.c
	gcc -ggdb -o callselect -static callselect.c

callstat64: callstat64.c
	gcc -ggdb -o callstat64 -static callstat64.c

callgetcwd: callgetcwd.c
	gcc -ggdb -o callgetcwd -static callgetcwd.c

call uname: calluname.c
	gcc -ggdb -o calluname -stat-c calluname.c

clean:
	- rm mtu_receiver_good
	- rm opensocket
	- rm *.strace
	- rm callread
	- rm callselect
	- rm callstat64
	- rm callllseek
	- rm callgetcwd
	- rm calluname
	- rm callgetrlimit
