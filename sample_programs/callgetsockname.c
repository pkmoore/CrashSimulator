#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(6666);
    if((bind(s, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
        perror("Bind failed");
        return -1;
    }
    struct sockaddr out;
    socklen_t outlen = sizeof(struct sockaddr);
    getsockname(s, &out, &outlen);
    if(outlen > sizeof(struct sockaddr)) {
        printf("Bad length!\n");
        return -1;
    }
    struct sockaddr_in* o = (struct sockaddr_in*)&out;
    printf("Socket bound to %s:%d\n",
           inet_ntoa(o->sin_addr),
           ntohs(o->sin_port));
    return 0;
}
