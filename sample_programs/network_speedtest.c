#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main()
{
    int sock;
    struct sockaddr_in server;
    char* message = "PING";

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Could not create socket");
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );

    //Connect to remote server
    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("connect failed: ");
        return 1;
    }

    if(send(sock, message, strlen(message), 0) < 0)
    {
        perror("Send failed: ");
        return 1;
    }
    close(sock);
    return 0;
}
