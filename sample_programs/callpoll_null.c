#include <stdio.h>
#include <poll.h>

int main() {
    int result = poll(0, 0, 5000);
    if(result == -1) {
        perror("Poll call error");
        return -1;
    }
    return 0;
}
