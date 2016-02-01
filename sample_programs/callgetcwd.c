#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>

int main() {
    char path[PATH_MAX];
    char* result = getcwd(path, sizeof(path));
    if(result == NULL) {
        printf("GETCWD FAILED!!\n");
    }
    else {
        printf("cwd: %s\n", path);
    }
    return 0;
}
