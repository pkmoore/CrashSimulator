#include "parse_strace.h"
#include <stdbool.h>
#include  <stdio.h>

int main() {
    bool result = is_socket_syscall("socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3");
    printf("%s\n", result ? "true" : "false");

    printf("%ld\n", extract_return_value("socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3"));

    return 0;
}
