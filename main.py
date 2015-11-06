from __future__ import print_function
import os
import sys
import re
import argparse
import binascii

import tracereplay
from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS

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

FILE_DESCRIPTORS = []

# Horrible hack
buffer_address = 0
buffer_size = 0

def noop_current_syscall(pid):
    tracereplay.poke_register(pid, tracereplay.ORIG_EAX, 20)

def write_buffer(pid, address, value, buffer_length):
    writes = [value[i:i+4] for i in range(0, len(value), 4)]
    for i in writes:
        data = int(binascii.hexlify(i), 16)
        tracereplay.poke_address(pid, address, data)
        address = address + 4

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

def default_syscall_handler(syscall_id, syscall_object, entering, pid):
    print('======')
    print('Syscall_ID: {}'.format(syscall_id))
    print('Looked Up Syscall Name: {}'.format(SYSCALLS[syscall_id]))
    print(syscall_object)
    print('Entering: {}'.format(entering))
    print('======')

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

def read_entry_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    buffer_address = tracereplay.peek_register(pid, tracereplay.ECX)
    buffer_size = tracereplay.peek_register(pid, tracereplay.EDX)
    noop_current_syscall(pid)
    #horrible hack to deal with the fact that nooping results in the exit handler not being called
    read_exit_handler(syscall_id, syscall_object, entering, pid)

def read_exit_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    write_buffer(pid, buffer_address, syscall_object.args[1].value.lstrip('"').rstrip('"'), buffer_size)

def validate_syscall(syscall_id, syscall_object):
    if syscall_object.name != SYSCALLS[syscall_id][4:]:
        raise Exception('Syscall validation failed: {0} is not {1}'.format(syscall_id, syscall_object.name))

def validate_subcall(subcall_id, syscall_object):
    print('Subcall: {0} Syscall Name: {1}'.format(subcall_id, syscall_object.name))
    print(syscall_object.original_line)
    if syscall_object.name != SOCKET_SUBCALLS[subcall_id][4:]:
        raise Exception('Subcall validation failed: {0} is not {1}'.format(subcall_id, syscall_object.name))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SYSCALLS!')
    parser.add_argument('-c',
                        '--command',
                        help='The command to be executed',
                        required=True)
    parser.add_argument('-t',
                        '--trace',
                        help='The system call trace to be replayed during the specified command',
                        required=True)
    args = vars(parser.parse_args())
    command = args['command']
    trace = args['trace']
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
            elif orig_eax == 20:
                system_calls.next()
                tracereplay.syscall(pid)
                continue
            if entering_syscall:
                syscall_object = system_calls.next()
            handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            tracereplay.syscall(pid)
