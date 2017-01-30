#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sockfd;
    struct sockaddr_in me;
    struct sockaddr_in them;
    socklen_t them_len;
    them_len = sizeof(them);
    unsigned char buffer[512];
    unsigned char addr_buffer[32];
    ssize_t byte_count;

    memset(buffer, 0, sizeof(buffer));

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket() call failed:");
        return -1;
    }
    printf("Socket FD: %d\n", sockfd);

    me.sin_family = AF_INET;
    me.sin_port = htons(5555);
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sockfd, (struct sockaddr*)&me, sizeof(me)) == -1) {
        perror("bind() call failed:");
        return -1;
    }

    printf("Preparing to receive\n");
    if((byte_count = recvfrom(sockfd,
                              buffer,
                              sizeof(buffer),
                              0, 
                              (struct sockaddr*)&them,
                              &them_len)) == -1) {
        perror("recvfrom() call failed:");
        return -1;
    }
    close(sockfd);

    inet_ntop(AF_INET, (void*)&them.sin_addr, addr_buffer, them_len);
    
    printf("byte_count: %d\n", byte_count);
    printf("them_len: %d\n", them_len);
    printf("them.sin_family: %d\n", them.sin_family);
    printf("them.sin_port: %d\n", them.sin_port);
    printf("them.sin_addr.s_addr: %s\n", addr_buffer);

    for(size_t i = 0; i < sizeof(buffer); i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
                                  
    return 0;
}
