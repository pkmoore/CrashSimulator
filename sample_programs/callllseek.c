#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    int fd = open("test.txt", O_RDONLY);
    loff_t result;
    int r = syscall(SYS__llseek, fd, 0, 2, &result, SEEK_SET);
    printf("r: %d\nresult: %d\n", r, (int)result);
    return 0;

}
