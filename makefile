cs: main.o parse_strace.o
	gcc  -Wall -ggdb -std=c99 -o cs main.o parse_strace.o

main.o: main.c
	gcc  -Wall -ggdb -std=c99 -c -o main.o main.c

parse_strace.o: parse_strace.h parse_strace.c
	gcc -Wall -ggdb -std=c99 -c -o parse_strace.o parse_strace.c

clean:
	- rm *.o
	- rm cs
