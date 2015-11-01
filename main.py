from __future__ import print_function
import os
import sys
import re
import tracereplay
import syscall_handlers
from syscall_dict import SYSCALLS

sys.path.append('./python_modules/posix-omni-parser/')
import Trace

#Constants
SYS_exit = 252
SYS_exit_group = 231

FILE_DESCRIPTORS = []

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

def validate_syscall(syscall_id, syscall_object):
    #The 102 bit is a hack to handle socket subcalls
    if syscall_object.name not in SYSCALLS[syscall_id][4:] and syscall_id != 102:
            raise Exception(str(syscall_id) + " is not " + syscall_object.name)

if __name__ == '__main__':
    command = sys.argv[1]
    trace = sys.argv[2]
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execlp(command, command, command)
    else:
        entering_syscall = True
        t = Trace.Trace(trace)
        system_calls = iter(t.syscalls)
        while next_syscall():
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            #This if statement is an ugly hack
            if orig_eax == SYS_exit_group or \
            SYSCALLS[orig_eax] == 'sys_execve' or \
            orig_eax == SYS_exit:
                system_calls.next()
                tracereplay.syscall(pid)
                continue
            if entering_syscall:
                syscall_object = system_calls.next()
            #validate_syscall(orig_eax, syscall_object)
            syscall_handlers.handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            tracereplay.syscall(pid)
