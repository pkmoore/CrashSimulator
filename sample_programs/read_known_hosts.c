#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    int f = open("/home/preston/.ssh/known_hosts",
                 O_RDWR|O_CREAT|O_APPEND,
                 0666);
    struct stat buf;
    fstat(f, &buf);
    int off_high = 0;
    int off_low = 0;
    loff_t result;
    syscall(140, f, off_high, off_low, &result, SEEK_SET);
    unsigned char buffer[4096];
    ssize_t r;
    r = read(f, buffer, sizeof(buffer));
    int f2 = open("./tmp",
                  O_RDWR|O_CREAT|O_APPEND,
                  0666);
    r = write(f2, buffer, r);

    return 0;
}
