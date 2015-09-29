#define _GNU_SOURCE

#ifndef PARSE_STRACE_H
#include "parse_strace.h"
#endif

#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int opt;
    bool c_present = false;
    char* command;
    bool t_present;
    char* trace;
    while((opt = getopt(argc, argv, "c:t:")) != -1) {
        switch(opt) {
            case 'c':
                command = optarg;
                c_present = true;
                break;
            case 't':
                trace = optarg;
                t_present = true;
                break;
        }
    }
    if(!(c_present) || (!t_present)) {
        printf("Invalid required arguments\n");
        printf("%s -c <command> -t <trace>\n", argv[0]);
        exit(1);
    }
    pid_t child;
    int status;
    bool insyscall = false;
    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if(execlp(command, command, NULL) == -1) {
            printf("Failed to execute command in child process\n");
        }
    }
    else {
        long int orig_eax;
        FILE* trace_file;
        if((trace_file = fopen(trace, "r")) == NULL) {
            printf("Failed to open trace file\n");
            exit(1);
        }
        char* line = NULL;
        size_t line_length = 0;
        while(true) {
            wait(&status);
            if(WIFEXITED(status)) {
                break;
            }
            orig_eax = ptrace(PTRACE_PEEKUSER, child, 4*ORIG_EAX);
            if(orig_eax == SYS_open) {
                if(!insyscall) {
                    if(getline(&line, &line_length, trace_file) <= 0) {
                        printf("Getline encountered an error or reached the end of the file");
                        exit(1);
                    }
                    while(!is_open_syscall(line)) {
                        free(line);
                        line_length = 0;
                        if(getline(&line, &line_length, trace_file) <= 0) {
                            printf("Getline encountered an error or reached the end of the file");
                            exit(1);
                        }
                    }
                    printf("Corresponding line: %s", line);
                    printf("Entering: %ld\n", orig_eax);
                    free(line);
                    line_length = 0;
                    insyscall = true;
                }
                else {
                    printf("Exiting: %ld\n", orig_eax);
                    printf("Trying to return: EAX: %ld\n", ptrace(PTRACE_PEEKUSER, child, 4*EAX, NULL));
                    insyscall = false;
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
        return 0;
    }
}
