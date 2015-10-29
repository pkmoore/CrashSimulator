#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buffer[8];
    read(STDIN_FILENO, buffer, sizeof(buffer));
    buffer[7] = '\0';
    printf("%s\n", buffer);
    return 0;
}
