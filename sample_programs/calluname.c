#define _GNU_SOURCE
#include <stdio.h>
#include <sys/utsname.h>

int main() {
    struct utsname s;
    int result = uname(&s);
    if(result == -1) {
        printf("Call to uname failed");
    }
    else {
        printf("%s\n", s.sysname);
        printf("%s\n", s.nodename);
        printf("%s\n", s.release);
        printf("%s\n", s.version);
        printf("%s\n", s.machine);
        printf("%s\n", s.domainname);
    }
    return 0;
}
