from __future__ import print_function
from time import strptime, mktime
import datetime
import os
import signal
import sys
import re
import argparse
import binascii
import logging
import base64
from struct import pack, unpack

import tracereplay
from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS
from errno_dict import ERRNO_CODES
from os_dict import OS_CONST, STAT_CONST

sys.path.append('./python_modules/posix-omni-parser/')
import Trace

FILE_DESCRIPTORS = [tracereplay.STDIN]

# Horrible hack
buffer_address = 0
buffer_size = 0
return_value = 0
system_calls = None
entering_syscall = True
pollfd_array_address = 0

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
                        ('socket', True): socket_subcall_entry_handler,
                        ('accept', True): accept_subcall_entry_handler,
                        ('bind', True): subcall_return_success_handler,
                        ('listen', True): subcall_return_success_handler,
                        ('recv', True): recv_subcall_entry_handler,
                        ('recvfrom', True): recvfrom_subcall_entry_handler,
                        ('setsockopt', True): subcall_return_success_handler,
                        ('send', True): subcall_return_success_handler,
                        ('connect', True): subcall_return_success_handler,
                        ('getsockopt', True): getsockopt_entry_handler,
                        ('sendmmsg', True): subcall_return_success_handler,
                        ('sendto', True): subcall_return_success_handler,
                        ('shutdown', True): shutdown_subcall_entry_handler,
                        ('getsockname', True): getsockname_entry_handler,
                       }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX);
    try:
        validate_subcall(subcall_id, syscall_object)
    except Exception as e:
        print(e)
        os.kill(pid, signal.SIGKILL)
        sys.exit(1)
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, pid)
    except KeyError:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('No handler for socket subcall %s %s', syscall_object.name, 'entry' if entering else 'exit')

def _exit(pid):
    os.kill(pid, signal.SIGKILL)
    sys.exit(1)

def getsockname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getsockname handler')
    # Pull out the info that we can check
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    fd = params[0]
    # We don't compare params[1] because it is the address of an empty buffer
    # We don't compare params[2] because it is the address of an out parameter
    # Get values from trace for comparison
    fd_from_trace = syscall_object.args[0].value
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    #Decide if this is a file descriptor we want to deal with
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got successful getsockname call')
            addr = params[1]
            logging.debug('Addr: %d', addr)
            sockfields = syscall_object.args[1].value
            family = sockfields[0].value
            port = int(sockfields[1].value)
            ip = sockfields[2].value
            logging.debug('Family: %s', family)
            logging.debug('Port: %d', port)
            logging.debug('Ip: %s', ip)
            if family != 'AF_INET':
                raise NotImplementedException('getsockname only supports AF_INET')
            tracereplay.populate_af_inet_sockaddr(pid,
                                                addr,
                                                port,
                                                ip)
        else:
            logging.debug('Got unsuccessful getsockname call')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def shutdown_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering shutdown entry handler')
    # Pull out the info we can check
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 2)
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # TODO: We need to check the 'how' parameter here
    # Check to make sure everything is the same 
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    # Decide if we want to replay this system call
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        try:
            FILE_DESCRIPTORS.remove(fd)
        except ValueError:
            pass
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def getsockopt_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getsockopt handler')
    # Pull out what we can compare
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd = params[0]
    fd_from_trace = int(syscall_object.args[0].value)
    # We don't check param[3] because it is an address of an empty buffer
    # We don't check param[4] because it is an address of an empty length
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    # This if is sufficient for now for the implemented options
    if params[1] != 1 or params[2] != 4:
        raise Exception('Unimplemented getsockopt level or optname')
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
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
    else:
        logging.info('Not replaying this system call')

# Generic handler for all calls that just need to return what they returned in
# the trace.
# Currently used by send, listen
# TODO: check this guy for required parameter checking
def subcall_return_success_handler(syscall_id, syscall_object, pid):
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

def close_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering close entry handler')
    # Pull out everything we can check
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    # Decide if this is a system call we want to replay
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got unsuccessful close call')
            fd = syscall_object.args[0].value
            try:
                FILE_DESCRIPTORS.remove(fd)
            except ValueError:
                pass
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def close_exit_handler(syscall_id, syscall_object, pid):
    pass

# TODO: There is a lot more checking to be done here
def socket_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering socket subcall entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # Only PF_INET and PF_LOCAL socket calls are handled
    execution_is_PF_INET = (params[0] == tracereplay.PF_INET)
    trace_is_PF_INET = (str(syscall_object.args[0]) == '[\'PF_INET\']')
    execution_is_PF_LOCAL = (params[0] == 1) #define PF_LOCAL 1
    trace_is_PF_LOCAL = (str(syscall_object.args[0]) == '[\'PF_LOCAL\']')
    logging.debug('Execution is PF_INET: %s', execution_is_PF_INET)
    logging.debug('Trace is PF_INET: %s', trace_is_PF_INET)
    logging.debug('Exeuction is PF_LOCAL: %s', execution_is_PF_LOCAL)
    logging.debug('Trace is PF_LOCAL: %s', trace_is_PF_LOCAL)
    if execution_is_PF_INET != trace_is_PF_INET:
        raise Exception('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    if execution_is_PF_LOCAL != trace_is_PF_LOCAL:
        raise Exception('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    # Decide if we want to deal with this socket call or not
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

def accept_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Checking if line from trace is interrupted accept')
    # Hack to fast forward through interrupted accepts
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted accept. Will advance past')
        syscall_object = system_calls.next()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'accept':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # Pull out everything we can check
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # We don't check param[1] because it is the address of a buffer
    # We don't check param[2] because it is the address of a length
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    # Decide if this is a system call we want to replay
    if fd in FILE_DESCRIPTORS:
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            ret = syscall_object.ret[0]
            if ret in FILE_DESCRIPTORS:
                raise Exception('Syscall object return value ({}) already exists in'
                                'tracked file descriptors list ({})'
                                .format(ret, FILE_DESCRIPTORS))
            FILE_DESCRIPTORS.append(ret)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def accept_exit_handler(syscall_id, syscall_object, pid):
    pass

def recv_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    # Pull out everything we can check
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # We don't check params[1] because it is the address of an empty buffer
    len = params[2]
    len_from_trace = syscall_object.args[2].value
    # We don't check params[3] because it is a flags field
    # Check to make everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    if len!= int(len_from_trace):
        raise Exception('Length from execution ({}) does not match '
                        'length from trace ({})'
                        .format(len, len_from_trace))
    # Decide if we want to replay this system call
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if params[0] not in FILE_DESCRIPTORS:
            raise Exception('Tried to recv from non-existant file descriptor')
        buffer_address = params[1]
        buffer_size = params[2]
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = fix_character_literals(data)
        write_buffer(pid, buffer_address, data, buffer_size)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def recvfrom_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    # Pull out everything we can check
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # We don't check params[1] because it is the address of an empty buffer
    len = params[2]
    len_from_trace = syscall_object.args[2].value
    # We don't check params[3] because it is a flags field
    # We don't check params[4] because it is the address of an empty buffer
    # We don't check params[5] because it is the address of a length
    addr = params[4]
    sockfields = syscall_object.args[4].value
    family = sockfields[0].value
    port = int(sockfields[1].value)
    ip = sockfields[2].value
    # Check to make everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    if len!= int(len_from_trace):
        raise Exception('Length from execution ({}) does not match '
                        'length from trace ({})'
                        .format(len, len_from_trace))
    # Decide if we want to replay this system call
    if fd in FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if params[0] not in FILE_DESCRIPTORS:
            raise Exception('Tried to recvfrom from non-existant file descriptor')
        buffer_address = params[1]
        buffer_size = params[2]
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = fix_character_literals(data)
        write_buffer(pid, buffer_address, data, buffer_size)
        tracereplay.populate_sock
        tracereplay.populate_af_inet_sockaddr(pid,
                                              addr,
                                              port,
                                              ip)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')

def read_entry_handler(syscall_id, syscall_object, pid):
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
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = fix_character_literals(data)
        write_buffer(pid, buffer_address, data, buffer_size)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug("Ignoring read call to untracked file descriptor")

# This thing must be here to handle exits for read calls that we let pass. This
# will go away once the new "open" machinery is in place and we intercept all
# calls to read.
def read_exit_handler(syscall_id, syscall_object, pid):
    pass

#Note: This handler only takes action on syscalls made to file descriptors we
#are tracking. Otherwise it simply does any required debug-printing and lets it
#execute
def write_entry_handler(syscall_id, syscall_object, pid):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    msg_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    msg_len = tracereplay.peek_register(pid, tracereplay.EDX)
    logging.debug('Child attempted to write to FD: %s', fd)
    logging.debug('Child\'s message stored at: %s', msg_addr)
    logging.debug('Child\'s message length: %s', msg_len)
    #print_buffer(pid, msg_addr, msg_len)
    if fd in FILE_DESCRIPTORS:
        logging.debug('We care about this file descriptor. No-oping...')
        noop_current_syscall(pid)
        logging.debug('Applying return conditions')
        apply_return_conditions(pid, syscall_object)

# Once again, this only has to be here until the new "open" machinery is in lace
def write_exit_handler(syscall_id, syscall_object, pid):
    pass

def llseek_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering llseek entry handler')
    result = int(syscall_object.args[2].value.strip('[]'))
    result_addr = int(tracereplay.peek_register(pid, tracereplay.ESI))
    logging.debug('result: %s', result)
    logging.debug('result_addr: %s', result_addr)
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful llseek call')
        logging.debug('Populating result')
        tracereplay.populate_llseek_result(pid, result_addr, result)
    else:
        logging.debug('Got unsucceesful llseek call')
    apply_return_conditions(pid, syscall_object)

def getcwd_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getcwd entry handler')
    array_addr = tracereplay.peek_register(pid, tracereplay.EBX)
    data = str(syscall_object.args[0].value.strip('"'))
    data_length = int(syscall_object.ret[0])
    noop_current_syscall(pid)
    if data_length != 0:
        logging.debug('Got successful getcwd call')
        logging.debug('Data: %s', data)
        logging.debug('Data length: %s', data_length)
        logging.debug('Populating character array')
        tracereplay.populate_char_buffer(pid,
                                         array_addr,
                                         data,
                                         data_length)
    else:
        logging.debug('Got unsuccessful getcwd call')
    apply_return_conditions(pid, syscall_object)

def readlink_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering readlink entry handler')
    array_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    data = str(syscall_object.args[0].value.strip('"'))
    data_length = int(syscall_object.ret[0])
    noop_current_syscall(pid)
    if data_length != -1:
        logging.debug('Got successful readlink call')
        logging.debug('Data: %s', data)
        logging.debug('Data length: %s', data_length)
        logging.debug('Populating character array')
        tracereplay.populate_char_buffer(pid,
                                         array_addr,
                                         data,
                                         data_length)
    else:
        logging.debug('Got unsuccessful readlink call')
    apply_return_conditions(pid, syscall_object)

# This handler assumes that uname cannot fail. The only documented way it can
# fail is if the buffer it is handed is somehow invalid. This code assumes that
# well written programs don't do this.
def uname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering uname handler')
    args = {x.value.split('=')[0]: x.value.split('=')[1]
            for x in syscall_object.args}
    args = {x.strip('{}'): y.strip('"{}') for x, y in args.iteritems()}
    logging.debug(args)
    address = tracereplay.peek_register(pid, tracereplay.EBX)
    noop_current_syscall(pid)
    tracereplay.populate_uname_structure(pid,
                                         address,
                                         args['sysname'],
                                         args['nodename'],
                                         args['release'],
                                         args['version'],
                                         args['machine'],
                                         args['domainname'])
    apply_return_conditions(pid, syscall_object)

def getrlimit_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getrlimit handler')
    cmd = syscall_object.args[0].value[0]
    if cmd != 'RLIMIT_STACK':
        os.kill(pid, signal.SIGKILL)
        raise Exception('Unimplemented getrlimit command {}'.format(cmd))
    addr = tracereplay.peek_register(pid, tracereplay.ECX)
    rlim_cur = syscall_object.args[1].value.strip('{')
    rlim_cur = rlim_cur.split('=')[1]
    if rlim_cur.find('*') == -1:
        os.kill(pid, signal.SIGKILL)
        raise Exception('Unimplemented rlim_cur format {}'.format(rlim_cur))
    rlim_cur = int(rlim_cur.split('*')[0]) * int(rlim_cur.split('*')[1])
    rlim_max = syscall_object.args[2].value.strip('}')
    rlim_max = rlim_max.split('=')[1]
    if rlim_max != 'RLIM_INFINITY':
        raise Exception('Unlimited rlim_max format {}'.format(rlim_max))
    rlim_max = 0x7fffffffffffffff
    logging.debug('rlim_cur: %s', rlim_cur)
    logging.debug('rlim_max: %x', rlim_max)
    logging.debug('Address: %s', addr)
    noop_current_syscall(pid)
    tracereplay.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
    apply_return_conditions(pid, syscall_object)

def ioctl_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering ioctl handler')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    logging.debug('ebx: %x', ebx)
    logging.debug('ecx: %x', ecx)
    logging.debug('edx: %x', edx)
    logging.debug('edi: %x', edi)
    logging.debug('esi: %x', esi)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        cmd = syscall_object.args[1].value
        c_iflags = syscall_object.args[2].value
        c_iflags = int(c_iflags[c_iflags.rfind('=')+1:], 16)
        c_oflags = syscall_object.args[3].value
        c_oflags = int(c_oflags[c_oflags.rfind('=')+1:], 16)
        c_cflags = syscall_object.args[4].value
        c_cflags = int(c_cflags[c_cflags.rfind('=')+1:], 16)
        c_lflags = syscall_object.args[5].value
        c_lflags = int(c_lflags[c_lflags.rfind('=')+1:], 16)
        c_line = syscall_object.args[6].value
        c_line = int(c_line[c_line.rfind('=')+1:])
        cc = syscall_object.args[7].value
        cc = cc[cc.rfind('=')+1:].strip('"}')
        cc = cc.replace('\\x', ' ').strip()
        cc = bytearray.fromhex(cc)
        cc_as_string =''.join('{:02x}'.format(x) for x in cc)
        cc = cc_as_string.decode('hex')
        logging.debug('pid: %s', pid)
        logging.debug('Addr: %s', addr)
        logging.debug('cmd: %s', cmd)
        logging.debug('c_iflags: %x', c_iflags)
        logging.debug('c_oflags: %s', c_oflags)
        logging.debug('c_cflags: %s', c_cflags)
        logging.debug('c_lflags: %s', c_lflags)
        logging.debug('c_line: %s', c_line)
        logging.debug('cc: %s', cc_as_string)
        logging.debug('len(cc): %s', len(cc))
        if 'TCGETS' not in cmd:
            raise NotImplementedError('Unsupported ioctl command')
        tracereplay.populate_tcgets_response(pid, addr, c_iflags, c_oflags,
                                            c_cflags,
                                            c_lflags,
                                            c_line,
                                            cc
                                            )
    apply_return_conditions(pid, syscall_object)

def statfs64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering statfs64 handler') 
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    logging.debug("EBX: %s, ECX: %s, EDX: %s, ESI: %s, EDI: %s",
                  ebx, ecx, edx, edi, esi)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful statfs64 call')
        f_type = syscall_object.args[2].value
        f_type = int(f_type[f_type.rfind('=')+1:].strip('{}'), 16)
        f_bsize = syscall_object.args[3].value
        f_bsize = int(f_bsize[f_bsize.rfind('=')+1:])
        f_blocks = syscall_object.args[4].value
        f_blocks = int(f_blocks[f_blocks.rfind('=')+1:])
        f_bfree = syscall_object.args[5].value
        f_bfree = int(f_bfree[f_bfree.rfind('=')+1:])
        f_bavail = syscall_object.args[6].value
        f_bavail = int(f_bavail[f_bavail.rfind('=')+1:])
        f_files = syscall_object.args[7].value
        f_files = int(f_files[f_files.rfind('=')+1:])
        f_ffree = syscall_object.args[8].value
        f_ffree = int(f_ffree[f_ffree.rfind('=')+1:])
        f_fsid1 = syscall_object.args[9].value
        f_fsid1 = int(f_fsid1[f_fsid1.rfind('=')+1:].strip('{}'))
        f_fsid2 = int(syscall_object.args[10].value.strip('{}'))
        f_namelen = syscall_object.args[11].value
        f_namelen = int(f_namelen[f_namelen.rfind('=')+1:])
        f_frsize = syscall_object.args[12].value
        f_frsize = int(f_frsize[f_frsize.rfind('=')+1:])
        f_flags = syscall_object.args[13].value
        f_flags = int(f_flags[f_flags.rfind('=')+1:].strip('{}'))
        logging.debug('pid: %d', pid)
        logging.debug('addr: %x', addr & 0xffffffff)
        logging.debug('f_type: %x', f_type)
        logging.debug('f_bsize: %s', f_bsize)
        logging.debug('f_blocks: %s', f_blocks)
        logging.debug('f_bfree: %s', f_bfree)
        logging.debug('f_bavail: %s', f_bavail)
        logging.debug('f_files: %s', f_files)
        logging.debug('f_ffree: %s', f_ffree)
        logging.debug('f_fsid1: %s', f_fsid1)
        logging.debug('f_fsid2: %s', f_fsid2)
        logging.debug('f_namelen: %s', f_namelen)
        logging.debug('f_frsize: %s', f_frsize)
        logging.debug('f_flags: %s', f_flags)
        tracereplay.populate_statfs64_structure(pid,
                                                addr,
                                                f_type,
                                                f_bsize,
                                                f_blocks,
                                                f_bfree,
                                                f_bavail,
                                                f_files,
                                                f_ffree,
                                                f_fsid1,
                                                f_fsid2,
                                                f_namelen,
                                                f_frsize,
                                                f_flags)
    apply_return_conditions(pid, syscall_object)

def lstat64_entry_handler(syscall_id, syscall_object, pid):
   logging.debug('Entering lstat64 handler') 
   noop_current_syscall(pid)
   if syscall_object.ret[0] != -1:
       logging.debug('Got successful lstat64 call')
       raise NotImplementedError('Successful lstat64 not supported')
   apply_return_conditions(pid, syscall_object)

def open_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering open entry handler')
    logging.debug('Filename from trace: %s', syscall_object.args[0].value .strip('"'))
    if syscall_object.ret[0] != -1:
        ebx = tracereplay.peek_register(pid, tracereplay.EBX)
        fn = peek_string(pid, ebx)
        logging.debug('Filename from execution: %s', fn)
        if fn == '/etc/resolv.conf':
            logging.debug('Got attempt to open resolv.conf')
            FILE_DESCRIPTORS.append(syscall_object.ret[0])

def open_exit_handler(syscall_id, syscall_object, pid):
    pass

def handle_syscall(syscall_id, syscall_object, entering, pid):
    logging.debug('Handling syscall')
    if syscall_id == 102:
        logging.debug('This is a socket subcall')
        ebx = tracereplay.peek_register(pid, tracereplay.EBX)
        logging.debug('Socketcall id from EBX is: %s', ebx)
        socketcall_handler(syscall_id, syscall_object, entering, pid)
        return
    ignore_list = [
                   20, #sys_getpid
                   91, #sys_munprotect
                   125, #sys_mprotect
                   243, #sys_set_thread_area
                   45,  #sys_brk
                   192, #sys_mmap_pgoff/mmap
                   174, #sys_rt_sigaction
                   175, #sys_rt_sigprocmask
                   119, #sys_sigreturn
                   13, #sys_time
                   126, #sys_sigprocmask
                   311, #set_robust_list
                   258, #set_tid_address
                   266, #set_clock_getres
                   240, #sys_futex
                   191, #!!!!!!!!! sys_getrlimit
                  ]
    handlers = {
                (5, True): open_entry_handler,
                (5, False): open_exit_handler,
                (85, True): readlink_entry_handler,
                (197, True): fstat64_entry_handler,
                (122, True): uname_entry_handler,
                (183, True): getcwd_entry_handler,
                (140, True): llseek_entry_handler,
                (10, True): syscall_return_success_handler,
                (33, True): syscall_return_success_handler,
                (199, True): syscall_return_success_handler,
                (200, True): syscall_return_success_handler,
                (201, True): syscall_return_success_handler,
                (202, True): syscall_return_success_handler,
                (4, True): write_entry_handler,
                (4, False): write_exit_handler,
                (3, True): read_entry_handler,
                (3, False): read_exit_handler,
                (6, True): close_entry_handler,
                (6, False): close_exit_handler,
                (168, True): poll_entry_handler,
                (54, True): ioctl_entry_handler,
                (195, True): stat64_entry_handler,
                (142, True): select_entry_handler,
                (82, True): select_entry_handler,
                (221, True): fcntl64_entry_handler,
                (196, True): lstat64_entry_handler,
                (268, True): statfs64_entry_handler
               }
    if syscall_id not in ignore_list:
        try:
            handlers[(syscall_id, entering)](syscall_id, syscall_object, pid)
        except KeyError as e:
            logging.error('Encountered un-ignored syscall with no handler: %s(%s)',
                          syscall_id,
                          syscall_object.name)
            os.kill(pid, signal.SIGKILL)
            raise e

def fstat64_entry_handler(syscall_id, syscall_object, pid):
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    logging.debug('EBX: %x', ebx)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    logging.debug('EDX: %x', edx)
    logging.debug('ESI: %x', esi)
    logging.debug('EDI: %x', edi)
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful fstat64 call')
    else:
        logging.debug('Got successful fstat64 call')
        st_dev1 = syscall_object.args[1].value
        st_dev1 = st_dev1[st_dev1.rfind('(')+1:]
        st_dev2 = syscall_object.args[2].value
        st_dev2 = st_dev2.strip(')')
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)
        #HACK: horrible hack to deal with rdev. Fix this later
        st_rdev1 = 0
        st_rdev2 = 0
        if 'st_rdev' in syscall_object.args[10].value:
            logging.debug('Line contains an rdev')
            st_rdev1 = syscall_object.args[10].value
            st_rdev1 = int(st_rdev1.split('=')[1].strip('makedev('))
            st_rdev2 = syscall_object.args[11].value
            st_rdev2 = int(st_rdev2.strip(')'))
            mid_args = list(syscall_object.args[3:10])
            mid_args = [x.value for x in mid_args]
            time_args = list(syscall_object.args[12:])
            time_args = [x.value for x in time_args]
            #sometimes size is 0 so we need to hardcode it
            mid_args_dict = {'st_size': 0}
            mid_args_dict.update({x.split('=')[0]: x.split('=')[1]
                                  for x in mid_args})
            mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
            mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
            time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
            time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                 '%Y/%m/%d-%H:%M:%S'))) \
                             for x, y in time_args_dict.iteritems()}
            logging.debug('st_rdev1: %s', st_rdev1)
            logging.debug('st_rdev2: %s', st_rdev2)
        else:
            mid_args = list(syscall_object.args[3:11])
            mid_args = [x.value for x in mid_args]
            time_args = list(syscall_object.args[11:])
            time_args = [x.value for x in time_args]
            mid_args_dict = {x.split('=')[0]: x.split('=')[1] for x in mid_args}
            mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
            mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
            time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
            time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                     '%Y/%m/%d-%H:%M:%S'))) \
                             for x, y in time_args_dict.iteritems()}
        logging.debug('Middle Args: %s', mid_args_dict)
        logging.debug('Time Args: %s', time_args_dict)
        noop_current_syscall(pid)
        logging.debug('Injecting values into structure')
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           mid_args_dict['st_blocks'],
                                           mid_args_dict['st_nlink'],
                                           mid_args_dict['st_gid'],
                                           mid_args_dict['st_blksize'],
                                           st_rdev1,
                                           st_rdev2,
                                           mid_args_dict['st_size'],
                                           mid_args_dict['st_mode'],
                                           mid_args_dict['st_uid'],
                                           mid_args_dict['st_ino'],
                                           time_args_dict['st_ctime'],
                                           time_args_dict['st_mtime'],
                                           time_args_dict['st_atime'])
    apply_return_conditions(pid, syscall_object)

def stat64_entry_handler(syscall_id, syscall_object, pid):
    if 'st_rdev' in syscall_object.original_line:
        raise Exception('stat64 handler can\'t deal with st_rdevs!!')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    logging.debug('EBX: %x', ebx)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    logging.debug('EDX: %x', edx)
    logging.debug('ESI: %x', esi)
    logging.debug('EDI: %x', edi)
    noop_current_syscall(pid)
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful stat64 call')
    else:
        logging.debug('Got successful stat64 call')
        st_dev1 = syscall_object.args[1].value
        st_dev1 = st_dev1[st_dev1.rfind('(')+1:]
        st_dev2 = syscall_object.args[2].value
        st_dev2 = st_dev2.strip(')')
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)
        mid_args = list(syscall_object.args[3:11])
        mid_args = [x.value for x in mid_args]
        time_args = list(syscall_object.args[11:])
        time_args = [x.value for x in time_args]
        mid_args_dict = {x.split('=')[0]: x.split('=')[1] for x in mid_args}
        mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
        mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
        time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
        time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                 '%Y/%m/%d-%H:%M:%S'))) \
                         for x, y in time_args_dict.iteritems()}
        logging.debug('Middle Args: %s', mid_args_dict)
        logging.debug('Time Args: %s', time_args_dict)
        logging.debug('Injecting values into structure')
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           mid_args_dict['st_blocks'],
                                           mid_args_dict['st_nlink'],
                                           mid_args_dict['st_gid'],
                                           mid_args_dict['st_blksize'],
                                           0,
                                           0,
                                           mid_args_dict['st_size'],
                                           mid_args_dict['st_mode'],
                                           mid_args_dict['st_uid'],
                                           mid_args_dict['st_ino'],
                                           time_args_dict['st_ctime'],
                                           time_args_dict['st_mtime'],
                                           time_args_dict['st_atime'])
    apply_return_conditions(pid, syscall_object)

def cleanup_st_mode(m):
    m = m.split('|')
    tmp = 0
    for i in m:
        if i[0] == '0':
            tmp = tmp | int(i, 8)
        else:
            tmp = tmp | STAT_CONST[i]
    return tmp

def fcntl64_entry_handler(syscall_id, syscall_object, pid):
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
def select_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering select entry handler')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted select. Will advance past')
        syscall_object = system_calls.next()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'select':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    readfds = syscall_object.args[1].value.strip('[]').split(' ')
    readfds = [None if x == 'NULL' else int(x) for x in readfds]
    logging.debug('readfds: %s', readfds)
    writefds = syscall_object.args[2].value.strip('[]').split(' ')
    writefds = [None if x == 'NULL' else int(x) for x in writefds]
    logging.debug('writefds: %s', writefds)
    exceptfds = syscall_object.args[3].value.strip('[]').split(' ')
    exceptfds = [None if x == 'NULL' else int(x) for x in exceptfds]
    logging.debug('exceptfds: %s', exceptfds)
    fd = int(syscall_object.original_line[
                                         syscall_object.original_line.rfind('[')
                                         :
                                         syscall_object.original_line.rfind(']')
                                         ].strip('[]) '))
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
def syscall_return_success_handler(syscall_id, syscall_object, pid):
    logging.debug('Using default "return success" handler')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)

def poll_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering poll entry handler')
    noop_current_syscall(pid)
    global pollfd_array_address
    pollfd_array_address = tracereplay.peek_register(pid, tracereplay.EBX)
    poll_exit_handler(syscall_id, syscall_object, pid)

def poll_exit_handler(syscall_id, syscall_object, pid):
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
    logging.debug('Applying return conditions')
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

def peek_bytes(pid, address, num_bytes):
    reads = num_bytes // 4
    remainder = num_bytes % 4
    data = ''
    for i in range(reads):
        data =  data + pack('<i', tracereplay.peek_address(pid, address))
        address = address + 4
    if remainder != 0:
        last_chunk = pack('<i', tracereplay.peek_address(pid, address))
        data = data + last_chunk[:remainder]
    return data

def peek_string(pid, address):
    data = ''
    while True:
        data =  data + pack('<i', tracereplay.peek_address(pid, address))
        address = address + 4
        if '\0' in data:
            data = data[:data.rfind('\0')]
            return data

def extract_socketcall_parameters(pid, address, num):
    params = []
    for i in range(num):
        params += [tracereplay.peek_address(pid, address)]
        address = address + 4
    logging.debug('Extracted socketcall parameters: %s', params)
    return params

def fix_character_literals(string):
    logging.debug('Cleaning up string')
    string = string.replace('\\n', '\n')
    string = string.replace('\\r', '\r')
    string = string.replace('\"', '"')
    logging.debug('Cleaned up string:')
    logging.debug(string)
    return string

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
        raise Exception('Syscall validation failed: from execution: {0}({1}) is not from trace: {2}' \
                        .format(SYSCALLS[syscall_id][4:], \
                                syscall_id, \
                                syscall_object.name))

def validate_subcall(subcall_id, syscall_object):
    if syscall_object.name not in SOCKET_SUBCALLS[subcall_id][4:]:
        raise Exception('Subcall validation failed: from execution: {0}({1}) is not from trace:{2}' \
                        .format(SOCKET_SUBCALLS[subcall_id][4:], \
                                subcall_id, \
                                syscall_object.name))

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
    command = args['command'].split(' ')
    trace = args['trace']
    loglevel = args['loglevel']
    if loglevel:
        numeric_level = getattr(logging, loglevel.upper(), None)
        print(numeric_level)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: {}'.format(loglevel))
        logging.basicConfig(stream=sys.stderr, level=numeric_level)
        logging.info('Logging engaged')
        tracereplay.enable_debug_output(numeric_level)
    logging.debug('About to spawn child process')
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execvp(command[0], command)
    else:
        t = Trace.Trace(trace)
        system_calls = iter(t.syscalls)
        logging.info('Parsed trace with %s syscalls', len(t.syscalls))
        logging.info('Entering syscall handling loop')
        while next_syscall():
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            logging.info('===')
            logging.info('Advanced to next system call')
            logging.info('System call id from execution: %d', orig_eax)
            logging.info('Looked up system call name: %s', SYSCALLS[orig_eax])
            logging.info('This is a system call %s',
                          'entry' if entering_syscall else 'exit')
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
                logging.info('System call name from trace: %s',
                             syscall_object.name)
                logging.debug('System call object contents:\n%s',
                              syscall_object)
            if orig_eax != 102:
                try:
                    validate_syscall(orig_eax, syscall_object)
                except Exception as e:
                    logging.debug('EBX {0:2x}:'.format(tracereplay.peek_register(pid, tracereplay.EBX)))
                    logging.debug('ECX {0:2x}:'.format(tracereplay.peek_register(pid, tracereplay.ECX)))
                    logging.debug('EDX {0:2x}:'.format(tracereplay.peek_register(pid, tracereplay.EDX)))
                    logging.debug('EDI {0:2x}:'.format(tracereplay.peek_register(pid, tracereplay.EDI)))
                    logging.debug('ESI {0:2x}:'.format(tracereplay.peek_register(pid, tracereplay.ESI)))
                    print(e)
                    os.kill(pid, signal.SIGKILL)
                    sys.exit(1)
            handle_syscall(orig_eax, syscall_object, entering_syscall, pid)
            entering_syscall = not entering_syscall
            logging.debug('Requesting next syscall')
            tracereplay.syscall(pid)
