from __future__ import print_function
import os
import signal
import sys
import argparse
import logging
import traceback
import ConfigParser

from tracereplay_python import *
from time_handlers import *
from send_handlers import *
from recv_handlers import *
from socket_handlers import *
from file_handlers import *
from kernel_handlers import *
from multiplex_handlers import *
from generic_handlers import *

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
        ('sendmmsg', True): sendmmsg_entry_handler,
        ('sendto', True): sendto_entry_handler,
        ('sendto', False): sendto_exit_handler,
        ('shutdown', True): shutdown_subcall_entry_handler,
        ('recvmsg', True): recvmsg_entry_handler,
        ('recvmsg', False): recvmsg_exit_handler,
        ('getsockname', True): getsockname_entry_handler,
        ('getsockname', False): getsockname_exit_handler,
        ('getpeername', True): getpeername_entry_handler
        }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX)
    validate_subcall(subcall_id, syscall_object)
    try:
        subcall_handlers[(syscall_object.name, entering)](syscall_id,
                                                          syscall_object,
                                                          pid)
    except KeyError:
        raise NotImplementedError('No handler for socket subcall %s %s',
                                  syscall_object.name,
                                  'entry' if entering else 'exit')


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
    validate_syscall(orig_eax, syscall_object)
    ignore_list = [
        20,   # sys_getpid
        125,  # sys_mprotect
        243,  # sys_set_thread_area
        174,  # sys_rt_sigaction
        175,  # sys_rt_sigprocmask
        119,  # sys_sigreturn
        126,  # sys_sigprocmask
        311,  # set_robust_list
        258,  # set_tid_address
        266,  # set_clock_getres
        240,  # sys_futex
        191,  # !!!!!!!!! sys_getrlimit
        ]
    handlers = {
        # ### These calls just get their return values checked ####
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

        # ###                                                  ####
        (15, True): syscall_return_success_handler,
        (78, True): gettimeofday_entry_handler,
        (13, True): time_entry_handler,
        (27, True): syscall_return_success_handler,
        (5, True): open_entry_handler,
        (5, False): open_exit_handler,
        (39, True): mkdir_entry_handler,
        (85, True): readlink_entry_handler,
        (146, True): writev_entry_handler,
        (146, False): writev_exit_handler,
        (197, True): fstat64_entry_handler,
        (197, False): fstat64_exit_handler,
        (122, True): uname_entry_handler,
        (183, True): getcwd_entry_handler,
        (140, True): llseek_entry_handler,
        (140, False): llseek_exit_handler,
        (42, True): pipe_entry_handler,
        (43, True): times_entry_handler,
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
        (41, True): dup_entry_handler,
        (41, False): dup_exit_handler,
        (340, True): prlimit64_entry_handler,
        (345, True): sendmmsg_entry_handler,
        (345, False): sendmmsg_exit_handler
        }
    if syscall_id not in ignore_list:
        try:
            handlers[(syscall_id, entering)](syscall_id, syscall_object, pid)
        except KeyError:
            raise NotImplementedError('Encountered un-ignored syscall {} '
                                      'with no handler: {}({})'
                                      .format('entry' if entering else 'exit',
                                              syscall_id,
                                              syscall_object.name))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SYSCALLS!')
    parser.add_argument('-f',
                        '--config-file',
                        help='Config file containing parameters',
                        required=False)
    parser.add_argument('-c',
                        '--command',
                        help='The command to be executed',
                        required=False)
    parser.add_argument('-t',
                        '--trace',
                        help='The system call trace to be replayed during the '
                        'specified command',
                        required=False)
    parser.add_argument('-l',
                        '--loglevel',
                        help='Level: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = vars(parser.parse_args())
    # Don't allow switches combined with config file option
    if (args.get('command') is not None or args.get('trace') is not None) \
       and args.get('config_file') is not None:
        parser.error('Cannot combine command/trace switches with'
                     'config  file option')
    # If we're going with switches, we must have both
    if args.get('command') is not None or args.get('trace') is not None:
        if not (args.get('command') is not None
                and args.get('trace') is not None):
            parser.error('Command and trace switches must be specified '
                         'together')
        command = args['command'].split(' ')
        trace = args['trace']
    # At this point we're not using switches so we MUST use a config file
    elif args.get('config_file') is not None:
        config_file = args['config_file']
        config = ConfigParser.ConfigParser()
        config.readfp(open(config_file))
        command = config.get('Replay', 'command')
        command = command.split(' ')
        trace = config.get('Replay', 'trace')
    else:
        parser.error('Neither switches nor config file specified')
    loglevel = args['loglevel']
    if loglevel:
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            try:
                TypeError('Invalid log level: {}'.format(loglevel))
            except:
                traceback.print_exc()
                sys.exit(1)
        logging.basicConfig(stream=sys.stderr, level=numeric_level)
        logging.info('Logging engaged')
        tracereplay.enable_debug_output(numeric_level)
    logging.debug('About to spawn child process')
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execvp(command[0], command)
    else:
        debug_printers = {
            5: open_entry_debug_printer,
            6: close_entry_debug_printer,
            4: write_entry_debug_printer,
            41: dup_entry_debug_printer,
            45: brk_entry_debug_printer,
            54: ioctl_entry_debug_printer,
            91: munmap_entry_debug_printer,
            102: socketcall_debug_printer,
            142: select_entry_debug_printer,
            174: rt_sigaction_entry_debug_printer,
            192: mmap2_entry_debug_printer,
            195: stat64_entry_debug_printer,
            197: fstat64_entry_debug_printer,
            221: fcntl64_entry_debug_printer
        }
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
            # This if statement is an ugly hack
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
            try:
                handle_syscall(orig_eax, syscall_object,
                               tracereplay.entering_syscall,
                               pid)
            except:
                traceback.print_exc()
                try:
                    debug_printers[orig_eax](pid, orig_eax, syscall_object)
                except KeyError:
                    logging.warning('This system call ({}) has no debug '
                                    'printer'.format(orig_eax))
                os.kill(pid, signal.SIGKILL)
                sys.exit(1)
            logging.info('# of System Calls Handled: %d',
                         tracereplay.handled_syscalls)
            tracereplay.entering_syscall = not tracereplay.entering_syscall
            logging.debug('Requesting next syscall')
            tracereplay.syscall(pid)
