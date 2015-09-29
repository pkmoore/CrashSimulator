cs: main.o
	gcc  -Wall -ggdb -std=c99 -o cs main.o

main.o: main.c
	gcc  -Wall -ggdb -std=c99 -c -o main.o main.c

clean:
	- rm *.o
	- rm cs
