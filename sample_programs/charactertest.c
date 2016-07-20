#include <stdio.h>
#include <string.h>

int main() {
    unsigned int i;
    unsigned char buffer[256];
    unsigned char buffer2[256];
    FILE* f = fopen("chartest.bin", "wb");
    for(i = 0; i < sizeof(buffer); i++) {
        buffer[i] = i;
    }
    fwrite(buffer, sizeof(unsigned char), sizeof(buffer), f);
    fclose(f);
    f = fopen("chartest.bin", "rb");
    fread(buffer2, sizeof(unsigned char), sizeof(buffer), f);
    for(i = 0; i < sizeof(buffer); i++) {
        if(buffer[i] != buffer2[i]) {
            printf("Failed byte comparison at position %d\n", i);
        }
        else {
            printf("%c", buffer2[i]);
            fflush(stdout);
        }
    }
    printf("\n");
    fflush(stdout);
    return 0;
}
