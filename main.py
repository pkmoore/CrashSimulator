from __future__ import print_function
import os
import sys
import re
import tracereplay
from system_call_dict import SYSCALLS

sys.path.append('./python_modules/posix-omni-parser/')
import Trace

#Constants
SYS_exit = 252
SYS_exit_group = 231

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

def default_syscall_handler(syscall_id, syscall_object, entering):
    print('======')
    print('Syscall_ID: ' + str(syscall_id))
    print('Looked Up Syscall Name: ' + SYSCALLS[orig_eax])
    print(syscall_object)
    print('======')

def handle_syscall(syscall_id, syscall_object, entering):
    handlers = {}
    try:
        handlers[syscall_id](syscall_id, syscall_object, entering)
    except KeyError:
        default_syscall_handler(syscall_id, syscall_object, entering)

def validate_syscall(syscall_id, syscall_object):
    #The 102 bit is a hack to handle socket subcalls
    if syscall_object.name not in SYSCALLS[syscall_id][4:] and syscall_id != 102:
            raise SyscallMismatchError(str(syscall_id) + " is not " + syscall_object.name)

class SyscallMismatchError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


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
            orig_eax = tracereplay.get_EAX(pid)
            #This if statement is an ugly hack
            if orig_eax == SYS_exit_group or \
            SYSCALLS[orig_eax] == 'sys_execve' or \
            orig_eax == SYS_exit:
                print('Ignoring entry/exit')
                system_calls.next()
                tracereplay.syscall(pid)
                continue
            if entering_syscall:
                syscall_object = system_calls.next()
            validate_syscall(orig_eax, syscall_object)
            handle_syscall(orig_eax, syscall_object, entering_syscall)
            entering_syscall = not entering_syscall
            tracereplay.syscall(pid)
