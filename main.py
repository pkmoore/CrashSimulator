from __future__ import print_function
import os
import signal
import sys
import re
import argparse
import binascii
import logging
from struct import pack, unpack

import tracereplay
from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS
from errno_dict import ERRNO_CODES
from os_dict import OS_CONST

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
                        ('bind', True): subcall_return_success_handler,
                        ('listen', True): subcall_return_success_handler,
                        ('recv', True): recv_subcall_entry_handler,
                        ('setsockopt', True): subcall_return_success_handler,
                        ('send', True): subcall_return_success_handler,
                        ('connect', True): subcall_return_success_handler,
                        ('getsockopt', True): getsockopt_entry_handler
                       }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX);
    validate_subcall(subcall_id, syscall_object)
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        logging.warn('No handler for socket subcall %s %s',
                     syscall_object.name,
                     'entry' if entering else 'exit')

def _exit(pid):
    os.kill(pid, signal.SIGKILL)
    sys.exit(1)

def getsockopt_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering getsockopt handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 5)
    if params[1] != 1 or params[2] != 4:
        raise Exception('Unimplemented getsockopt level or optname')
    optval_addr = params[3]
    optval_len_addr = params[4]
    logging.debug('Optval addr: %s', optval_addr)
    logging.debug('Optval len addr: %s', optval_len_addr)
    optval = syscall_object.args[3].value.strip('[]')
    optval_len = syscall_object.args[4].value.strip('[]')
    logging.debug('Optval: %s', optval)
    logging.debug('Optval Length: %s', optval_len)
    noop_current_syscall(pid)
    logging.debug('Writing values')
    write_buffer(pid,
                 optval_addr,
                 optval,
                 optval_len)
    write_buffer(pid,
                 optval_len_addr,
                 optval_len,
                 4)
    apply_return_conditions(pid, syscall_object)

# Generic handler for all calls that just need to return what they returned in
# the trace.
# Currently used by send, listen
def subcall_return_success_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering subcall return success handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 1)
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution differs from file '
                        'descriptor from trace')
    if fd not in FILE_DESCRIPTORS:
        raise Exception('Called {} on untracked file descriptor' \
                        .format(syscall_object.name))
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)

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
    apply_return_conditions(pid, syscall_object)

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
    execution_is_PF_LOCAL = (params[0] == 1) #define PF_LOCAL 1
    trace_is_PF_LOCAL = (str(syscall_object.args[0]) == '[\'PF_LOCAL\']')
    logging.debug('Execution is PF_INET: %s', execution_is_PF_INET)
    logging.debug('Trace is PF_INET: %s', trace_is_PF_INET)
    logging.debug('Exeuction is PF_LOCAL: %s', execution_is_PF_LOCAL)
    logging.debug('Trace is PF_LOCAL: %s', trace_is_PF_LOCAL)
    if execution_is_PF_INET != trace_is_PF_INET:
        raise Exception('Encountered socket subcall with mismatch between \
                             execution and trace protocol family')
    if execution_is_PF_LOCAL != trace_is_PF_LOCAL:
        raise Exception('Encountered socket subcall with mismatch between \
                             execution and trace protocol family')
    if trace_is_PF_INET or \
       execution_is_PF_INET or \
       trace_is_PF_LOCAL or \
       execution_is_PF_LOCAL:
        noop_current_syscall(pid)
        fd = syscall_object.ret
        logging.debug('File Descriptor from trace: %s', fd)
        if fd not in FILE_DESCRIPTORS:
            FILE_DESCRIPTORS.append(fd[0])
        else:
            raise Exception('File descriptor from trace is already tracked')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Ignoring non-PF_INET call to socket')

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
    write_buffer(pid,
                 buffer_address,
                 syscall_object.args[1].value.lstrip('"').rstrip('"'),
                 buffer_size)
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
    if syscall_id == 102:
        logging.debug('This is a socket subcall')
        ebx = tracereplay.peek_register(pid, tracereplay.EBX)
        logging.debug('EBX value is: %s', ebx)
    logging.debug('Syscall name (from trace): %s', syscall_object.name)
    handlers = {
                (3, True):read_entry_handler,
                (102, True): socketcall_handler,
                (102, False): socketcall_handler,
                (6, True): close_entry_handler,
                (6, False): close_exit_handler,
                (168, True): poll_entry_handler,
                (54, True): syscall_return_success_handler,
                (195, True): syscall_return_success_handler,
                (142, True): select_entry_handler,
                (82, True): select_entry_handler,
                (221, True): fcntl64_entry_handler
               }
    try:
        handlers[(syscall_id, entering)](syscall_id, syscall_object, entering, pid)
    except KeyError:
        pass

def fcntl64_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering fcntl64 entry handler')
    operation = syscall_object.args[1].value[0].strip('[]\'')
    noop_current_syscall(pid)
    if operation == 'F_GETFL' or operation == 'F_SETFL':
        apply_return_conditions(pid, syscall_object)
    else:
        raise NotImplementedError('Unimplemented fcntl64 operation {}'
                                  .format(operation))

# A lot of the parsing in this function needs to be moved into the
# posix-omni-parser codebase. there really needs to be an "ARRAY OF FILE
# DESCRIPTORS" parsing class.
def select_entry_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Entering select entry handler')
    readfds = syscall_object.args[1].value.strip('[]').split(' ')
    readfds = [None if x == 'NULL' else int(x) for x in readfds]
    logging.debug('readfds: %s', readfds)
    writefds = syscall_object.args[2].value.strip('[]').split(' ')
    writefds = [None if x == 'NULL' else int(x) for x in writefds]
    logging.debug('writefds: %s', writefds)
    exceptfds = syscall_object.args[3].value.strip('[]').split(' ')
    exceptfds = [None if x == 'NULL' else int(x) for x in exceptfds]
    logging.debug('exceptfds: %s', exceptfds)
    fd = int(syscall_object.original_line[syscall_object.original_line \
                                                     .rfind('['):] \
                                                     .strip('[]) '))
    logging.debug('Got active file descriptor: %s', fd)
    readfds_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('readfds addr: %s', readfds_addr)
    writefds_addr = tracereplay.peek_register(pid, tracereplay.EDX)
    logging.debug('writefds addr: %s', writefds_addr)
    exceptfds_addr = tracereplay.peek_register(pid, tracereplay.ESI)
    logging.debug('exceptfds addr: %s', exceptfds_addr)

    if fd in readfds:
        logging.debug('using readfds_addr')
        addr = readfds_addr
    elif fd in writefds:
        logging.debug('using writefds_addr')
        addr = writefds_addr
    else:
        logging.debug('using exceptfds_addr')
        addr = exceptfds_addr
    logging.debug('Using Address: %s', addr)
    noop_current_syscall(pid)
    logging.debug('Populating bitmaps')
    tracereplay.populate_select_bitmaps(pid, fd, addr)
    logging.debug('Injecting return value: {}'.format(syscall_object.ret[0]))
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])

# Like the subcall return success handler, this handler just no-ops out a call
# and returns whatever it returned from the trace. Used by ioctl and stat64
def syscall_return_success_handler(syscall_id, syscall_object, entering, pid):
    logging.debug('Using default "return success" handler')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)

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

# This function leaves the child process in a state of waiting at the point just
# before execution returns to user code.
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

# Applies the return conditions from the specified syscall object to the syscall
# currently being executed by the process identified by PID. Return conditions
# at this point are: setting the return value appropriately. Setting the value
# of errno by suppling -ERROR in the eax register. This function should only be
# called in exit handlers.
def apply_return_conditions(pid, syscall_object):
    ret_val = syscall_object.ret[0]
    if  syscall_object.ret[0] == -1  and syscall_object.ret[1] is not None:
        logging.debug('Got non-None errno value: %s', syscall_object.ret[1])
        error_code = ERRNO_CODES[syscall_object.ret[1]];
        logging.debug('Looked up error number: %s', error_code)
        ret_val = -error_code
        logging.debug('Will return: %s instead of %s',
                      ret_val,
                      syscall_object.ret[0])
    else:
        ret_val = cleanup_return_value(ret_val)
    logging.debug('Injecting return value %s', ret_val)
    tracereplay.poke_register(pid, tracereplay.EAX, ret_val)

def cleanup_return_value(val):
    try:
        ret_val = int(val)
    except ValueError:
        logging.debug('Couldn\'t parse ret_val as base 10 integer')
        try:
            ret_val = int(val, base=16)
        except ValueError:
            logging.debug('Couldn\'t parse ret_val as base 16 either')
            try:
                logging.debug('Trying to look up ret_val')
                ret_val = OS_CONST[val]
            except KeyError:
                logging.debug('Couldn\'t look up value from OS_CONST dict')
                raise Exception('Couldn\'t get integer form of return value!')
    logging.debug('Cleaned up value %s', ret_val)
    return ret_val

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
    if syscall_id == 268 and 'stat' in syscall_object.name:
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
            logging.debug('===')
            logging.debug('New system call')
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            logging.debug('Extracted %s from ORIG_EAX', orig_eax)
            logging.debug('%s', entering_syscall)
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
