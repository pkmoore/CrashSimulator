#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdlib.h>

int main() {
    struct  addrinfo* ai;
    int result = getaddrinfo("http://www.google.com", "80", NULL, &ai);
    if(result == -1) {
        perror("Failed: ");
        exit(1);
    }
    result = getaddrinfo("http://www.toast.com", "80", NULL, &ai);
    if(result == -1) {
        perror("Failed: ");
        exit(1);
    }
    printf("Worked\n");
    return 0;
}
