#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main() {

    char template[] = "testXXXXXX";
    int fd = mkstemp(template);
    printf("%s\n", template);
    close(fd);
    unlink(template);
    return 0;
}
