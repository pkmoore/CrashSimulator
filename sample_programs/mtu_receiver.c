#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main() {
    int s, c;
    struct addrinfo* info;
    ssize_t received;
    char message[256];
    if(getaddrinfo("127.0.0.1", "6666", NULL, &info) != 0) {
        printf("Failed to get addrinfo\n");
        exit(1);
    }
    s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if(bind(s, info->ai_addr, info->ai_addrlen) == -1) {
        printf("Bind failed!\n");
        exit(1);
    }
    if(listen(s, 1) == -1) {
        printf("Listen failed!\n");
        exit(1);
    }
    freeaddrinfo(info);
    if((c = accept(s, NULL, NULL)) == -1) {
        printf("Accept failed!\n");
        exit(1);
    }
    if((received = recv(c, &message, (sizeof(message) - 1), 0)) == -1) {
        printf("Receive failed!\n");
        exit(1);
    }
    message[received] = '\0';
    close(c);
    close(s);
    printf("Got: %s\n", message);
    return 0;
}
