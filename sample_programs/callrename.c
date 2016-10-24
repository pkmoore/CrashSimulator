#include <stdio.h>

int main() {
    FILE* fp = fopen("test.txt", "w");
    char* msg = "test\n";
    fwrite(msg, 1, 5, fp);
    fclose(fp);
    rename("test.txt", "test2.txt");
    unlink("test2.txt");
    printf("Worked\n");
    return 0;
}