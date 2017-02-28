all: callrename opensocket mtu_receiver_good callread callselect callstat64 callllseek callgetcwd calluname callgetrlimit calltcgets callstatfs64 callgetsockname callpoll_null callgetaddrinfo callsetlocale nonblock charactertest callselect_noaction read_known_hosts dropbear_read_calls callreaddir callgetdents64 setsockoptchristmas callrecvfrom network_speedtest filesystem_speedtest calllstat64

calllstat64: calllstat64.c
	gcc -ggdb -o calllstat64 -static calllstat64.c

filesystem_speedtest: filesystem_speedtest.c
	gcc -std=c11 -ggdb -o filesystem_speedtest filesystem_speedtest.c

network_speedtest: network_speedtest.c
	gcc -std=c11 -ggdb -o network_speedtest network_speedtest.c

callrecvfrom: callrecvfrom.c
	gcc -std=c11 -ggdb -o callrecvfrom callrecvfrom.c

setsockoptchristmas: setsockoptchristmas.c
	gcc -ggdb -o setsockoptchristmas setsockoptchristmas.c

callgetdents64: callgetdents64.c
	gcc -ggdb -o callgetdents64 callgetdents64.c

callreaddir: callreaddir.c
	gcc -ggdb -o callreaddir callreaddir.c

callrename: callrename.c
	gcc -ggdb -o callrename callrename.c

dropbear_read_calls: dropbear_read_calls.c
	gcc -ggdb -o dropbear_read_calls dropbear_read_calls.c

read_known_hosts: read_known_hosts.c
	gcc -ggdb -o read_known_hosts read_known_hosts.c

callselect_noaction: callselect_noaction.c
	gcc -ggdb -o callselect_noaction callselect_noaction.c

charactertest: charactertest.c
	gcc -ggdb -o charactertest charactertest.c

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
	- rm callrename
	- rm callreaddir
	- rm setsockoptchristmas
	- rm callrecvfrom
	- rm network_speedtest
	- rm filesystem_speedtest
