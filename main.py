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
pollfd_array_address = 0

def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
                        ('socket', True): socket_subcall_entry_handler,
                        ('accept', True): accept_subcall_entry_handler,
                        ('bind', True): bind_subcall_entry_handler,
                        ('listen', True): subcall_return_success_handler,
                        ('recv', True): recv_subcall_entry_handler,
                        ('setsockopt', True): setsockopt_entry_handler,
                        ('send', True): subcall_return_success_handler
                       }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX);
    validate_subcall(subcall_id, syscall_object)
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        logging.warn('No handler for socket subcall %s %s',
                     syscall_object.name,
                     'entry' if entering else 'exit')

# Generic handler for all calls that just need to return what they returned in
# the trace.
# Currently used by send, listen
def subcall_return_success_handler(syscall_id, syscall_object, entering, pid):
    noop_current_syscall(pid)
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def bind_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering bind subcall entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address: %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 3)
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution differs from file '
                        'descriptor from trace')
    if fd not in FILE_DESCRIPTORS:
        raise Exception('Execution attempted to bind untracked file descriptor \
                         {}'.format(fd))
    noop_current_syscall(pid)
    bind_subcall_exit_handler(syscall_id, syscall_object, entering, pid)

def bind_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering bind subcall exit handler')
    logging.debug('Injecting return value: %s', syscall_object.ret[0])
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def close_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering close entry handler')
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd in FILE_DESCRIPTORS:
        if fd != int(fd_from_trace):
            raise Exception('File descriptor from execution differs from file '
                            'descriptor from trace')
        logging.debug('Got tracked file descriptor')
        noop_current_syscall(pid)
        close_exit_handler(syscall_id, syscall_object, entering, pid)
    else:
        logging.debug('Ignoring close of non-socket file descriptor')

def close_exit_handler(syscall_id, syscall_object, entering, pid):
    fd = syscall_object.args[0].value
    try:
        FILE_DESCRIPTORS.remove(fd)
    except ValueError:
        pass
    logging.debug('Injecting return value: %s', syscall_object.ret[0])
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def socket_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    #Before we proceed we need to make sure this is socket call we care about.
    #In order to do this we must that the executing call has the correct first
    #parameter (PF_INET) and that the corresponding line in the trace has the
    #same
    logging.debug('Entering socket subcall entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address: %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 3)
    execution_is_PF_INET = (params[0] == tracereplay.PF_INET)
    trace_is_PF_INET = (str(syscall_object.args[0]) == '[\'PF_INET\']')
    logging.debug('Execution is PF_INET: %s', execution_is_PF_INET)
    logging.debug('Trace is PF_INET: %s', trace_is_PF_INET)
    if execution_is_PF_INET != trace_is_PF_INET:
        raise Exception('Encountered socket subcall with mismatch between \
                             execution and trace protocol family')
    if trace_is_PF_INET or execution_is_PF_INET:
        noop_current_syscall(pid)
        socket_subcall_exit_handler(syscall_id, syscall_object, entering, pid)
    else:
        logging.info('Ignoring non-PF_INET call to socket')

def socket_subcall_exit_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering socket subcall exit handler')
    fd = syscall_object.ret
    logging.debug('File Descriptor from trace: %s', fd)
    if fd not in FILE_DESCRIPTORS:
        FILE_DESCRIPTORS.append(fd[0])
    else:
        raise Exception('File descriptor from trace is already tracked')
    logging.debug('Injecting return value: %s', syscall_object.ret[0])
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def setsockopt_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering setsockopt subcall handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution differs from file '
                        'descriptor from trace')
    if fd not in FILE_DESCRIPTORS:
        raise Exception('Called setsockopt on untracked file descriptor')
    noop_current_syscall(pid)
    setsockopt_exit_handler(syscall_id, syscall_object, entering, pid)

def setsockopt_exit_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering setsockopt exit handler')
    logging.debug('Injecting return value: %s', syscall_object.ret[0])
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def accept_subcall_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Checking if line from trace is interrupted accept')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted accept. Will advance past')
        syscall_object = system_calls.next()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'accept':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
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

def read_entry_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    global return_value
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd in FILE_DESCRIPTORS:
        if fd != int(fd_from_trace):
            raise Exception('File descriptor from execution differs from file '
                            'descriptor from trace')
        buffer_address = tracereplay.peek_register(pid, tracereplay.ECX)
        buffer_size = tracereplay.peek_register(pid, tracereplay.EDX)
        noop_current_syscall(pid)
        return_value = syscall_object.ret[0]
        read_exit_handler(syscall_id, syscall_object, entering, pid)
    else:
        logging.debug("Ignoring read call to untracked file descriptor")

def read_exit_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    global return_value
    write_buffer(pid, buffer_address, syscall_object.args[1].value.lstrip('"').rstrip('"'), buffer_size)
    tracereplay.poke_register(pid, tracereplay.EAX, return_value)

def handle_syscall(syscall_id, syscall_object, entering, pid):
    logging.debug('Sycall id: %s', syscall_id)
    logging.debug('Syscall name (from trace): %s', syscall_object.name)
    handlers = {
                (3, True):read_entry_handler,
                (102, True): socketcall_handler,
                (102, False): socketcall_handler,
                (6, True): close_entry_handler,
                (6, False): close_exit_handler,
                (168, True): poll_entry_handler,
               }
    try:
        handlers[(syscall_id, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        pass

def poll_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering poll entry handler')
    noop_current_syscall(pid)
    global pollfd_array_address
    pollfd_array_address = tracereplay.peek_register(pid, tracereplay.EBX)
    poll_exit_handler(syscall_id, syscall_object, entering, pid)

def poll_exit_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering poll exit handler')
    ol = syscall_object.original_line
    ret_struct = ol[ol.rfind('('):]
    logging.debug('Poll return structure: %s', ret_struct)
    fd = int(ret_struct[ret_struct.find('=') + 1:ret_struct.find(',')])
    logging.debug('Returned file descriptor: %s', fd)
    ret_struct = ret_struct[ret_struct.find(' '):]
    revent = ret_struct[ret_struct.find('=') + 1 : ret_struct.find('}')]
    if revent != 'POLLIN':
        raise NotImplementedError('Encountered unimplemented revent in poll')
    logging.debug('Returned event: %s', revent)
    logging.debug('Writing poll results structure')
    global pollfd_array_address
    logging.debug('Address: %s', pollfd_array_address)
    logging.debug('File Descriptor: %s', fd)
    logging.debug('Event: %s', tracereplay.POLLIN)
    logging.debug('Child PID: %s', pid)
    tracereplay.write_poll_result(pid,
                                  pollfd_array_address,
                                  fd,
                                  tracereplay.POLLIN
                                 )
    logging.debug('Injecting return value: {}'.format(syscall_object.ret[0]))
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

def noop_current_syscall(pid):
    logging.debug('Nooping the current system call in pid: %s', pid)
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

def print_buffer(pid, address, num_bytes):
    reads = num_bytes // 4
    remainder = num_bytes % 4
    data = ''
    for i in range(reads):
        data =  data + pack('<I', tracereplay.peek_address(pid, address))
        address = address + 4
    if remainder != 0:
        last_chunk = pack('<I', tracereplay.peek_address(pid, address))
        data = data + last_chunk[:remainder]
    print(data)

def extract_socketcall_parameters(pid, address, num):
    params = []
    for i in range(num):
        params += [tracereplay.peek_address(pid, address)]
        address = address + 4
    logging.debug('Extracted socketcall parameters: %s', params)
    return params

def validate_syscall(syscall_id, syscall_object):
    if syscall_id == 192 and 'mmap' in syscall_object.name:
        return
    if syscall_id == 140 and 'llseek' in syscall_object.name:
        return
    if syscall_id == 195 and 'stat' in syscall_object.name:
        return
    if syscall_object.name not in SYSCALLS[syscall_id][4:]:
        raise Exception('Syscall validation failed: {0} is not {1}' \
                        .format(syscall_id, syscall_object.name))

def validate_subcall(subcall_id, syscall_object):
    if syscall_object.name not in SOCKET_SUBCALLS[subcall_id][4:]:
        raise Exception('Subcall validation failed: {0}({1}) is not {2}' \
                        .format(SOCKET_SUBCALLS[subcall_id][4:], \
                                subcall_id, \
                                syscall_object.name))\

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
    parser.add_argument('-o',
                        '--child-output',
                        help='File in which to write child process\' output. \
                        Default is "child_output.log"')
    args = vars(parser.parse_args())
    command = args['command'].split(' ')
    trace = args['trace']
    loglevel = args['loglevel']
    child_output = args['child_output']
    if loglevel:
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(loglevel))
        logging.basicConfig(stream=sys.stderr, level=numeric_level)
        logging.info('Logging engaged')
        tracereplay.enable_debug_output()
    logging.debug('About to spawn child process')
    pid = os.fork()
    if pid == 0:
        f = open(child_output if child_output else 'child_output.log', 'w', 0)
        os.dup2(f.fileno(), 1)
        os.dup2(f.fileno(), 2)
        tracereplay.traceme()
        os.execvp(command[0], command)
    else:
        t = Trace.Trace(trace)
        system_calls = iter(t.syscalls)
        logging.info('Parsed trace with %s syscalls', len(t.syscalls))
        logging.info('Entering syscall handling loop')
        while next_syscall():
            logging.debug('New system call')
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            logging.debug('Extracted %s from ORIG_EAX', orig_eax)
            #This if statement is an ugly hack
            if SYSCALLS[orig_eax] == 'sys_exit_group' or \
               SYSCALLS[orig_eax] == 'sys_execve' or \
               SYSCALLS[orig_eax] == 'sys_exit':
                logging.debug('Ignoring syscall')
                system_calls.next()
                tracereplay.syscall(pid)
                continue
            if entering_syscall:
                syscall_object = system_calls.next()
                logging.debug('Selecting next syscall from trace\n%s',
                              syscall_object)
            if orig_eax != 102:
                logging.debug('Validating non-socketcall syscall')
                validate_syscall(orig_eax, syscall_object)
            logging.debug('Handling syscall')
            handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            logging.debug('Requesting next syscall')
            tracereplay.syscall(pid)
