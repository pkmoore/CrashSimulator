#include <stdio.h>
#include <termios.h>
int main() {
    struct termios t;
    int result = ioctl(1, 0x5401, &t);
    printf("%x\n", t.c_iflag);
    printf("%x\n", t.c_oflag);
    printf("%x\n", t.c_cflag);
    printf("%x\n", t.c_lflag);
    printf("%x\n", t.c_line);
    int i;
    for(i = 0; i < sizeof(t.c_cc); i++) {
        printf("%02x ", t.c_cc[i]);
    }
    printf("\n");
    return 0;
}
        
