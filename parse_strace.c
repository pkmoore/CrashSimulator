#ifndef PARSE_STRACE_H
#include "parse_strace.h"
#endif

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bool is_open_syscall(char* line) {
    regex_t regex;
    if(regcomp(&regex, "open(", 0) == -1) {
        printf("Failed to compile is_open_syscall regex");
        exit(1);
    }
    int ret = regexec(&regex, line, 0, NULL, 0);
    regfree(&regex);
    if(ret == 0) {
        return true;
    }
    else if (ret == REG_NOMATCH) {
        return false;
    }
    else {
        printf("is_open_syscall match attempt failed");
        exit(1);
    }
}


