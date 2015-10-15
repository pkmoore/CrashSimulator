#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
int main() {
    int s, c;
    struct addrinfo* info;
    struct addrinfo hints;
    ssize_t received;
    ssize_t ret;
    char message[256];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if(getaddrinfo(NULL, "6666", NULL, &info) != 0) {
        perror("Error:");
        printf("Failed to get addrinfo\n");
        exit(1);
    }
    s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if(bind(s, info->ai_addr, info->ai_addrlen) == -1) {
        perror("Error:");
        printf("Bind failed!\n");
        exit(1);
    }
    if(listen(s, 1) == -1) {
        perror("Error:");
        printf("Listen failed!\n");
        exit(1);
    }
    freeaddrinfo(info);
    if((c = accept(s, NULL, NULL)) == -1) {
        perror("Error:");
        printf("Accept failed!\n");
        exit(1);
    }
    received = 0;
    while(received < 255) {
        if((ret = recv(c, message + received, (sizeof(message) - 1 - received), 0)) == -1) {
            perror("Error:");
            printf("Receive failed!\n");
            close(c);
            close(s);
            exit(1);
        }
        received += ret;
        printf("Received Total: %d\n", received);
    }
    message[received] = '\0';
    close(c);
    close(s);
    printf("Got: %s\n", message);
    return 0;
}
