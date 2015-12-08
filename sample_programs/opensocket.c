#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s != -1) {
        printf("Success!\n");
    }
    else {
        printf("Failure!\n");
    }
    return 0;
}
