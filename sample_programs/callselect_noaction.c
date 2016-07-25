#include <stdio.h>
#include <sys/select.h>

int main() {
    fd_set r;
    fd_set w;
    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_SET(0, &r);
    FD_SET(1, &w);
    FD_SET(2, &w); 
    int res = select(4, &r, &w, NULL, 
                    
    printf("Worked!\n");
    return 0;
}
