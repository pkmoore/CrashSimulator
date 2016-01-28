#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    struct stat64 s;
    printf("Address of s: %p\n", &s);
    printf("Sizeof stat64: %d\n", sizeof(struct stat64));
    printf("sizeof int: %d\n", sizeof(int));
    stat64("./test.txt", &s);
    printf("---------------------------\n");
    printf("st_dev: %x\n", (int)s.st_dev);
    printf("st_ino: %x\n", (int)s.st_ino);
    printf("st_mode: %x\n", (int)s.st_mode);
    printf("st_nlink: %x\n", (int)s.st_nlink);
    printf("st_uid: %x\n", (int)s.st_uid);
    printf("st_gid: %x\n", (int)s.st_gid);
    printf("st_size: %x\n", (int)s.st_size);
    printf("st_blksize: %x\n", (int)s.st_blksize);
    printf("st_blocks: %x\n", (int)s.st_blocks);
    printf("st_ctime: %x\n", (int)s.st_ctime);
    printf("st_mtime: %x\n", (int)s.st_mtime);
    printf("st_atime: %x\n", (int)s.st_atime);
    return 0;
}
