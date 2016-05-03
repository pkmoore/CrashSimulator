from __future__ import print_function
import datetime
import os
import signal
import sys
import re
import argparse
import logging
import base64

from tracereplay_python import *
from time_handlers import *
from send_handlers import *
from recv_handlers import *
from socket_handlers import *
from file_handlers import *
from kernel_handlers import *

from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS
from errno_dict import ERRNO_CODES
from os_dict import OS_CONST, STAT_CONST

sys.path.append('./python_modules/posix-omni-parser/')
import Trace

def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
                        ('socket', True): socket_subcall_entry_handler,
                        ('socket', False): socket_exit_handler,
                        ('accept', True): accept_subcall_entry_handler,
                        ('bind', True): bind_entry_handler,
                        ('bind', False): bind_exit_handler,
                        ('listen', True): subcall_return_success_handler,
                        ('recv', True): recv_subcall_entry_handler,
                        ('recvfrom', True): recvfrom_subcall_entry_handler,
                        ('setsockopt', True): subcall_return_success_handler,
                        ('send', True): subcall_return_success_handler,
                        ('connect', True): subcall_return_success_handler,
                        ('getsockopt', True): getsockopt_entry_handler,
                        ('sendmmsg', True): subcall_return_success_handler,
                        ('sendto', True): sendto_entry_handler,
                        ('sendto', False): sendto_exit_handler,
                        ('shutdown', True): shutdown_subcall_entry_handler,
                        ('recvmsg', True): recvmsg_entry_handler,
                        ('recvmsg', False): recvmsg_exit_handler,
                        ('getsockname', True): getsockname_entry_handler,
                        ('getsockname', False): getsockname_exit_handler,
                        ('getpeername', True): getpeername_entry_handler
                       }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX);
    try:
        validate_subcall(subcall_id, syscall_object)
    except ReplayDeltaError as e:
        os.kill(pid, signal.SIGKILL)
        logging.derror(e)
        sys.exit(1)
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id, syscall_object, pid)
    except KeyError:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('No handler for socket subcall %s %s', syscall_object.name, 'entry' if entering else 'exit')
    print(tracereplay.peek_register(pid, tracereplay.EAX))

def handle_syscall(syscall_id, syscall_object, entering, pid):
    logging.debug('Handling syscall')
    if entering:
        tracereplay.handled_syscalls += 1
    if syscall_id == 102:
        logging.debug('This is a socket subcall')
        ebx = tracereplay.peek_register(pid, tracereplay.EBX)
        logging.debug('Socketcall id from EBX is: %s', ebx)
        socketcall_handler(syscall_id, syscall_object, entering, pid)
        return
    logging.debug('Checking syscall against execution')
    try:
        validate_syscall(orig_eax, syscall_object)
    except ReplayDeltaError as e:
        os.kill(pid, signal.SIGKILL)
        logging.error(e)
        sys.exit(1)
    ignore_list = [
                   20, #sys_getpid
                   125, #sys_mprotect
                   243, #sys_set_thread_area
                   174, #sys_rt_sigaction
                   175, #sys_rt_sigprocmask
                   119, #sys_sigreturn
                   126, #sys_sigprocmask
                   311, #set_robust_list
                   258, #set_tid_address
                   266, #set_clock_getres
                   240, #sys_futex
                   191, #!!!!!!!!! sys_getrlimit
                  ]
    handlers = {
                #### These calls just get their return values checked ####
                (9, True): check_return_value_entry_handler,
                (9, False): check_return_value_exit_handler,

                (192, True): check_return_value_entry_handler,
                (192, False): check_return_value_exit_handler,

                (195, True): check_return_value_entry_handler,
                (195, False): check_return_value_exit_handler,

                (45, True): check_return_value_entry_handler,
                (45, False): check_return_value_exit_handler,

                (91, True): check_return_value_entry_handler,
                (91, False): check_return_value_exit_handler,

                (33, True): check_return_value_entry_handler,
                (33, False): check_return_value_exit_handler,

                (125, True): check_return_value_entry_handler,
                (125, False): check_return_value_exit_handler,

                ####                                                  ####
                (78, True): gettimeofday_entry_handler,
                (13, True): time_entry_handler,
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
                (195, False): stat64_exit_handler,
                (142, True): select_entry_handler,
                (82, True): select_entry_handler,
                (221, True): fcntl64_entry_handler,
                (196, True): lstat64_entry_handler,
                (268, True): statfs64_entry_handler,
                (265, True): clock_gettime_entry_handler,
                (345, True): sendmmsg_entry_handler,
                (345, False): sendmmsg_exit_handler
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

# A lot of the parsing in this function needs to be moved into the
# posix-omni-parser codebase. there really needs to be an "ARRAY OF FILE
# DESCRIPTORS" parsing class.
def select_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering select entry handler')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted select. Will advance past')
        syscall_object = tracereplay.system_calls.next()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'select':
            os.kill(pid, signal.SIGKILL)
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
    pollfd_array_address = tracereplay.peek_register(pid, tracereplay.EBX)
    ol = syscall_object.original_line
    ret_struct = ol[ol.rfind('('):]
    logging.debug('Poll return structure: %s', ret_struct)
    fd = int(ret_struct[ret_struct.find('=') + 1:ret_struct.find(',')])
    logging.debug('Returned file descriptor: %s', fd)
    ret_struct = ret_struct[ret_struct.find(' '):]
    revent = ret_struct[ret_struct.find('=') + 1 : ret_struct.find('}')]
    if syscall_object.args[1].value != 1:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('encountered more (or less) ' \
                                  'than one poll struct')
    if revent not in ['POLLIN', 'POLLOUT']:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('Encountered unimplemented revent in poll')
    logging.debug('Returned event: %s', revent)
    logging.debug('Writing poll results structure')
    logging.debug('Address: %s', pollfd_array_address)
    logging.debug('File Descriptor: %s', fd)
    logging.debug('Event: %s', revent)
    logging.debug('Child PID: %s', pid)
    if revent == 'POLLIN':
        r = tracereplay.POLLIN
    else:
        r = tracereplay.POLLOUT
    tracereplay.write_poll_result(pid,
                                  pollfd_array_address,
                                  fd,
                                  r
                                 )
    apply_return_conditions(pid, syscall_object)

def check_return_value_entry_handler(syscall_id, syscall_object, pid):
    pass

def check_return_value_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering check_return_value exit handler')
    ret_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    logging.debug('Return value from execution %x', ret_from_execution)
    logging.debug('Return value from trace %x', ret_from_trace)
    if ret_from_execution < 0:
        ret_from_execution = ret_from_execution & 0xffffffff
    if ret_from_execution != ret_from_trace:
        raise Exception('Return value from execution ({}) differs from '
                        'return value from trace ({})' \
                        .format(ret_from_execution, ret_from_trace))

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
        if not isinstance(numeric_level, int):
            raise TypeError('Invalid log level: {}'.format(loglevel))
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
        tracereplay.system_calls = iter(t.syscalls)
        logging.info('Parsed trace with %s syscalls', len(t.syscalls))
        logging.info('Entering syscall handling loop')
        while next_syscall():
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            logging.info('===')
            logging.info('Advanced to next system call')
            logging.info('System call id from execution: %d', orig_eax)
            logging.info('Looked up system call name: %s', SYSCALLS[orig_eax])
            logging.info('This is a system call %s',
                          'entry' if tracereplay.entering_syscall else 'exit')
            #This if statement is an ugly hack
            if SYSCALLS[orig_eax] == 'sys_exit_group' or \
               SYSCALLS[orig_eax] == 'sys_execve' or \
               SYSCALLS[orig_eax] == 'sys_exit':
                logging.debug('Ignoring syscall')
                tracereplay.system_calls.next()
                tracereplay.syscall(pid)
                continue
            if tracereplay.entering_syscall:
                syscall_object = tracereplay.system_calls.next()
                logging.info('System call name from trace: %s',
                             syscall_object.name)
                logging.debug('System call object contents:\n%s',
                              syscall_object)
            if orig_eax == 5:
                print(peek_string(pid, tracereplay.peek_register(pid, tracereplay.EBX)))
            handle_syscall(orig_eax, syscall_object, tracereplay.entering_syscall, pid)
            logging.info('# of System Calls Handled: %d',
                         tracereplay.handled_syscalls)
            tracereplay.entering_syscall = not tracereplay.entering_syscall
            logging.debug('Requesting next syscall')
            tracereplay.syscall(pid)
