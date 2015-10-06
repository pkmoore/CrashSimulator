#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
int main() {
    int s;
    struct addrinfo* info;
    ssize_t sent;
    char message[] = "Test message\n";
    if(getaddrinfo("127.0.0.1", "6666", NULL, &info) != 0) {
        printf("Failed to get addrinfo\n");
        exit(1);
    }
    s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if(connect(s, info->ai_addr, info->ai_addrlen) == -1) {
        printf("Connect failed!\n");
        exit(1);
    }
    freeaddrinfo(info);
    if((sent = send(s, message, strlen(message), 0)) == -1) {
        printf("Send failed!\n");
        exit(1);
    }
    close(s);
    return 0;
}
