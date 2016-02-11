// Apparently this is another one of those cases where I have to define _GNU_SOURCE to make things work correctly
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/statfs.h>
#include <sys/types.h>

int main() {
    struct statfs64 s;
    int result = statfs64(".", &s);
    if(result == -1) {
        printf("Statfs call failed!\n");
    }
    else {
        printf("sizeof(__SWORD_TYPE): %d\n", sizeof(__SWORD_TYPE));
        printf("sizeof(fsblkcnt_t): %d\n", sizeof(fsblkcnt_t));
        printf("sizeof(fsfilcnt_t): %d\n", sizeof(fsfilcnt_t));
        printf("sizeof(fsid_t): %d\n", sizeof(fsid_t));
        printf("sizeof(long): %d\n", sizeof(long));
        printf("sizeof(int): %d\n", sizeof(int));
        printf("sizeof(struct statfs): %d\n", sizeof(struct statfs));
        printf("sizeof(s.f_spare): %d\n", sizeof(s.f_spare));
        printf("f_type: %d\n", s.f_type);    /* type of filesystem (see below) */
        printf("f_bsize: %d\n", s.f_bsize);   /* optimal transfer block size */
        printf("f_blocks: %d\n", s.f_blocks);  /* total data blocks in filesystem */
        printf("f_bfree: %d\n", s.f_bfree);   /* free blocks in fs */
        printf("f_bavail: %d\n", s.f_bavail);  /* free blocks available to unprivileged user */
        printf("f_files: %d\n", s.f_files);   /* total file nodes in filesystem */
        printf("f_ffree: %d\n", s.f_ffree);   /* free file nodes in fs */
        printf("f_fsid: %d\n", s.f_fsid);    /* filesystem id */
        printf("f_namelen: %d\n", s.f_namelen); /* maximum length of filenames */
        printf("f_frsize: %d\n", s.f_frsize);  /* fragment size (since Linux 2.6) */
        printf("f_flags:d %d\n", s.f_flags);
        printf("f_spare: ");
        int i;
        for(i = 0; i < (sizeof(s.f_spare) / sizeof(long)); i++) {
            printf("%d ", s.f_spare[i]);
        }
        printf("\n");
        return 0;
    }
}
