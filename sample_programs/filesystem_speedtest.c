#include <stdio.h>
#include <unistd.h>

int main() {
    FILE  *fp = fopen("tmp_deleteme.txt", "w");
    fprintf(fp, "WRITE");
    fclose(fp);
    unlink("tmp_deleteme.txt");
    return 0;
}
