#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

int main() {
    int f = open("./test.txt", O_RDWR, 0666);
    unsigned char buffer[128];
    int i;
    ssize_t r;
    r = read(f, buffer, 1);
    i = 1;
    while(r > 0) {
        r = read(f, buffer+i, 1); 
        i++;
    }
    i--;
    int j;
    //for(j = 0; j < i; j++) {
    //    printf("%02X ", buffer[j]);
    //}
    //printf("\n");
    for(j = 0; j < i; j++) {
        printf("%c", buffer[j]);
    }
    fflush(stdout);
    return 0;
}
