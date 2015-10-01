#define PARSE_STRACE_H

#include <stdbool.h>

bool is_socket_syscall(char* line);
long extract_return_value(char* line);
