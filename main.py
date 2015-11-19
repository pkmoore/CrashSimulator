from __future__ import print_function
import os
import sys
import re
import argparse
import binascii
import logging
from struct import pack, unpack

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

FILE_DESCRIPTORS = [tracereplay.STDIN]

# Horrible hack
buffer_address = 0
buffer_size = 0
return_value = 0
system_calls = None
entering_syscall = True

def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
                        ('socket', True): socket_subcall_entry_handler,
                        ('accept', True): accept_subcall_entry_handler,
                        ('bind', True): bind_subcall_entry_handler,
                        ('listen', True): listen_subcall_entry_handler,
                        ('recv', True): recv_subcall_entry_handler,
                       }
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        raise NotImplementedError('No handler for socket subcall {}'
                                  .format(syscall_object.name))

def listen_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    noop_current_syscall(pid)
    listen_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def listen_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def bind_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    noop_current_syscall(pid)
    bind_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def bind_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def close_entry_handler(syscall_id, syscall_object, entering, pid):
    pass

def close_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.args[0].value
    try:
        FILE_DESCRIPTORS.remove(fd)
    except ValueError:
        pass

def socket_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    noop_current_syscall(pid)
    socket_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def socket_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    if syscall_object.args[0] ==  '[\'PF_INET\']':
        fd = syscall_object.ret
        if fd not in FILE_DESCRIPTORS:
            FILE_DESCRIPTORS.append(fd[0])
        else:
            raise Exception('Tried to store the same file descriptor twice')
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def accept_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    noop_current_syscall(pid)
    accept_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def accept_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.ret
    if fd not in FILE_DESCRIPTORS:
        FILE_DESCRIPTORS.append(fd[0])
    else:
        raise Exception('Tried to store the same file descriptor twice')
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def recv_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    global return_value
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    noop_current_syscall(pid)
    if params[0] not in FILE_DESCRIPTORS:
        raise Exception('Tried to recv from non-existant file descriptor')
    buffer_address = params[1]
    buffer_size = params[2]
    return_value = syscall_object.ret[0]
    recv_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def recv_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    global return_value
    write_buffer(pid, buffer_address, syscall_object.args[1].value.lstrip('"').rstrip('"'), buffer_size)
    tracereplay.poke_register(pid, tracereplay.EAX, return_value)

def handle_syscall(syscall_id, syscall_object, entering, pid):
    handlers = {
                (102, True): socketcall_handler,
                (102, False): socketcall_handler,
                (6, True): close_entry_handler,
                (6, False): close_exit_handler,
               }
    try:
        handlers[(syscall_id, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        pass

def noop_current_syscall(pid):
    tracereplay.poke_register(pid, tracereplay.ORIG_EAX, 20)
    tracereplay.syscall(pid)
    next_syscall()
    skipping = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
    if skipping != 20:
        raise Exception('Nooping did not result in getpid exit. Got {}'.format(skipping))
    global entering_syscall
    entering_syscall = False

# Just for the record, this function is a monstrosity.
def write_buffer(pid, address, value, buffer_length):
    writes = [value[i:i+4] for i in range(0, len(value), 4)]
    trailing = len(value) % 4
    if trailing != 0:
        left = writes.pop()
    for i in writes:
        i = i[::-1]
        data = int(binascii.hexlify(i), 16)
        tracereplay.poke_address(pid, address, data)
        address = address + 4
    if trailing != 0:
        address = address
        data = tracereplay.peek_address(pid, address)
        d = pack('i', data)
        d = left + d[len(left):]
        tracereplay.poke_address(pid, address, unpack('i', d)[0])

def extract_socketcall_parameters(pid, address, num):
    params = []
    for i in range(num):
        params += [tracereplay.peek_address(pid, address)]
        address = address + 4
    return params

def validate_syscall(syscall_id, syscall_object):
    if syscall_id == 192 and 'mmap' not in syscall_object.name:
        raise Exception('Syscall validation failed: {0} is not {1}'.format(syscall_id, syscall_object.name))
    if syscall_object.name not in SYSCALLS[syscall_id][4:]:
        raise Exception('Syscall validation failed: {0} is not {1}'.format(syscall_id, syscall_object.name))

def validate_subcall(subcall_id, syscall_object):
    if syscall_object.name not in SOCKET_SUBCALLS[subcall_id][4:]:
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
    parser.add_argument('-l',
                        '--loglevel',
                        help='Log Level: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = vars(parser.parse_args())

    if args['loglevel']:
        numeric_level = getattr(logging, args['loglevel'].upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(loglevel))
        logging.basicConfig(stream=sys.stderr, level=numeric_level)
        logging.info('logging engaged')
    command = args['command'].split(' ')
    trace = args['trace']
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execvp(command[0], command)
    else:
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
            if orig_eax != 102:
                validate_syscall(orig_eax, syscall_object)
            handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            tracereplay.syscall(pid)
