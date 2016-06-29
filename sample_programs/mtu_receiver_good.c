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
    struct sockaddr_in addr;
    ssize_t received;
    ssize_t ret;
    char message[16];

    s = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("Error:");
        printf("Bind failed!\n");
        exit(1);
    }
    if(listen(s, 1) == -1) {
        perror("Error:");
        printf("Listen failed!\n");
        exit(1);
    }
    if((c = accept(s, NULL, NULL)) == -1) {
        perror("Error:");
        printf("Accept failed!\n");
        exit(1);
    }
    received = 0;
    while(received < 16) {
        ret = recv(c, message + received, (sizeof(message) - 1 - received), 0);
        if(ret == -1) {
            perror("Error:");
            printf("Receive failed!\n");
            close(c);
            close(s);
            exit(1);
        }
        received += ret;
        printf("Received Total: %d\n", received);
        if(ret == 0) {
            break;
        }
    }
    message[received] = '\0';
    close(c);
    close(s);
    printf("Got: %s\n", message);
    return 0;
}
