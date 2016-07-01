all: opensocket mtu_receiver_good callread callselect callstat64 callllseek callgetcwd calluname callgetrlimit calltcgets callstatfs64 callgetsockname callpoll_null callgetaddrinfo callsetlocale nonblock

nonblock: nonblock.c
	gcc -ggdb -o nonblock nonblock.c

callsetlocale: callsetlocale.c
	gcc -ggdb -o callsetlocale callsetlocale.c

callgetaddrinfo: callgetaddrinfo.c
	gcc -ggdb -o callgetaddrinfo callgetaddrinfo.c

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

calluname: calluname.c
	gcc -ggdb -o calluname -static calluname.c

calltcgets: calltcgets.c
	gcc -ggdb -o calltcgets -static calltcgets.c

callstatfs64: callstatfs64.c
	gcc -ggdb -o callstatfs64 -static callstatfs64.c

callgetsockname: callgetsockname.c
	gcc -ggdb -o callgetsockname -static callgetsockname.c

callpoll_null: callpoll_null.c
	gcc -ggdb -o callpoll_null -static callpoll_null.c

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
	- rm calltcgets
	- rm callstatfs64
	- rm callgetsockname
	- rm callpoll_null
	- rm callsetlocale
