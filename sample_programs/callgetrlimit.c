#define _GNU_SOURCE
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

int main() {
    struct rlimit r;
    int result = getrlimit(RLIMIT_STACK, &r);
    if(result == -1) {
        printf("Call to getrlimit failed");
    }
    else {
        printf("cur: %lld\n", (long long)r.rlim_cur);
        printf("max: %lld\n", (long long)r.rlim_max);
    }
    return 0;
}
