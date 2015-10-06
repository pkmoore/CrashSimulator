#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    //This third argument should cause an error
    int s = socket(AF_INET, SOCK_STREAM, 500);
    printf("Socket returned %d\n", s);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6666);
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr);
    int retval = bind(s, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if(retval == 0) {
        printf("success\n");
    }
    else {
        printf("Failure\n");
    }
    return 0;
}
