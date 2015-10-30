from __future__ import print_function
import os
import sys
import re
import tracereplay
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

def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
                        ('socket', True): socket_subcall_entry_handler,
                        ('socket', False): socket_subcall_exit_handler,
                        ('accept', True): accept_subcall_entry_handler,
                        ('accept', False): accept_subcall_exit_handler
                       }
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        default_syscall_handler(syscall_id, syscall_object, entering, pid)

def close_entry_handler(syscall_id, syscall_object, entering, pid):
    pass

def close_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.args[0].value
    try:
        FILE_DESCRIPTORS.remove(fd)
    except ValueError:
        pass

def socket_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    pass

def socket_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    if syscall_object.args[0] ==  '[\'PF_INET\']':
        fd = syscall_object.ret
        if fd not in FILE_DESCRIPTORS:
            FILE_DESCRIPTORS.append(fd[0])
        else:
            raise Exception('Tried to store the same file descriptor twice')

def open_entry_handler(syscall_id, syscall_object, entering, pid):
    pass

def open_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.ret
    if fd not in FILE_DESCRIPTORS:
        FILE_DESCRIPTORS.append(fd[0])
    else:
        raise Exception('Tried to store the same file descriptor twice')

def accept_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    pass

def accept_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.ret
    if fd not in FILE_DESCRIPTORS:
        FILE_DESCRIPTORS.append(fd[0])
    else:
        raise Exception('Tried to store the same file descriptor twice')

# Horrible hack
buffer_address = 0
buffer_size = 0

def read_entry_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    buffer_address = tracereplay.get_ECX(pid)
    buffer_size = tracereplay.get_EDX(pid)
    pass

def read_exit_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    tracereplay.poke_address(pid, buffer_address, 0x41414141)
    pass

def default_syscall_handler(syscall_id, syscall_object, entering, pid):
    pass
    #print('======')
    #print('Syscall_ID: ' + str(syscall_id))
    #print('Looked Up Syscall Name: ' + SYSCALLS[orig_eax])
    #print(syscall_object)
    #print('======')

def handle_syscall(syscall_id, syscall_object, entering, pid):
    handlers = {
                (102, True): socketcall_handler,
                (102, False): socketcall_handler,
                (6, True): close_entry_handler,
                (6, False): close_exit_handler,
                (5, True): open_entry_handler,
                (5, False): open_exit_handler,
                (3, True): read_entry_handler,
                (3, False): read_exit_handler
               }
    try:
        handlers[(syscall_id, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        default_syscall_handler(syscall_id, syscall_object, entering, pid)

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
            orig_eax = tracereplay.get_EAX(pid)
            #This if statement is an ugly hack
            if orig_eax == SYS_exit_group or \
            SYSCALLS[orig_eax] == 'sys_execve' or \
            orig_eax == SYS_exit:
                system_calls.next()
                tracereplay.syscall(pid)
                continue
            if entering_syscall:
                syscall_object = system_calls.next()
            validate_syscall(orig_eax, syscall_object)
            handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            tracereplay.syscall(pid)
