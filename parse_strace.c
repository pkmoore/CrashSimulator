#ifndef PARSE_STRACE_H
#include "parse_strace.h"
#endif

#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool is_socket_syscall(char* line) {
    regex_t regex;
    int ret;
    if(regcomp(&regex, "socket(", 0) == -1) {
        printf("Failed to compile is_socket_syscall regex");
        exit(1);
    }
    ret = regexec(&regex, line, 0, NULL, 0);
    regfree(&regex);
    if(ret == 0) {
        return true;
    }
    else if (ret == REG_NOMATCH) {
        return false;
    }
    else {
        printf("is_socket_syscall match attempt failed");
        exit(1);
    }
}

long extract_return_value(char* line) {
    int ret;
    regex_t regex;
    regmatch_t match[1];

    if(regcomp(&regex, " = -?[a-zA-Z0-9]* ?", REG_EXTENDED) == -1) {
        printf("Failed to compile extrace_return_value regex");
        exit(1);
    }
    ret = regexec(&regex, line, 1, match, 0);
    if(ret == 0) {
        char text[strlen(line) + 1];
        memset(&text, 0, sizeof(text));
        strncpy(text, line+match[0].rm_so, match[0].rm_eo - match[0].rm_so);
        char text_return_value[strlen(line) + 1];
        memset(&text_return_value, 0, sizeof(text_return_value));
        strncpy(text_return_value, &text[3], (strlen(text) - 3));
        return strtol(text_return_value, NULL, 0);
    }
    else if(ret == REG_NOMATCH){
        printf("Return value not found in line!\n");
        exit(1);
    }
    else {
        printf("extrace_return_value match attempt failed");
        exit(1);
    }
}
