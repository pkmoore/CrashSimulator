#define _GNU_SOURCE

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
    while((opt = getopt(argc, argv, "c:")) != -1) {
        switch(opt) {
            case 'c':
                command = optarg;
                c_present = true;
                break;
        }
    }
    if(!(c_present)) {
        printf("Invalid required arguments\n");
        printf("%s -c <command>\n", argv[0]);
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
        while(true) {
            wait(&status);
            if(WIFEXITED(status)) {
                break;
            }
            orig_eax = ptrace(PTRACE_PEEKUSER, child, 4*ORIG_EAX);
            if(orig_eax == SYS_open) {
                if(!insyscall) {
                    printf("Entering: %ld\n", orig_eax);
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
