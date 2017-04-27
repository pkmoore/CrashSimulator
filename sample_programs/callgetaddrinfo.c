#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdlib.h>

int main() {
    struct  addrinfo* ai;
    int result = getaddrinfo("http://www.reddit.com", "80", NULL, &ai);
    if(result == -1) {
        perror("Failed: ");
        exit(1);
    }
    unsigned char* ai_idx = (unsigned char*)ai;
    int i;
    for(i = 0; i < sizeof(struct addrinfo); i++) {
        printf("%02x ", ai_idx[i]);
    }
    printf("\n");

    printf("Worked\n");
    return 0;
}
