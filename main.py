from __future__ import print_function

import ConfigParser
import argparse
import signal
import sys
import traceback
from tracereplay import cinterface as cint

from file_handlers import *
from generic_handlers import *
from kernel_handlers import *
from multiplex_handlers import *
from recv_handlers import *
from send_handlers import *
from socket_handlers import *
from time_handlers import *

from util import *

sys.path.append('./python_modules/posix-omni-parser/')
import Trace


def socketcall_handler(syscall_id, syscall_object, entering, pid):
    subcall_handlers = {
        ('socket', True): socket_subcall_entry_handler,
        ('socket', False): socket_exit_handler,
        ('accept', True): accept_subcall_entry_handler,
        ('accept', False): accept_subcall_entry_handler,
        ('bind', True): bind_entry_handler,
        ('bind', False): bind_exit_handler,
        ('listen', True): listen_entry_handler,
        ('listen', False): listen_exit_handler,
        ('recv', True): recv_subcall_entry_handler,
        ('recvfrom', True): recvfrom_subcall_entry_handler,
        ('setsockopt', True): setsockopt_entry_handler,
        ('send', True): send_entry_handler,
        ('send', False): send_exit_handler,
        ('connect', True): connect_entry_handler,
        ('connect', False): connect_exit_handler,
        ('getsockopt', True): getsockopt_entry_handler,
        # ('sendmmsg', True): sendmmsg_entry_handler,
        ('sendto', True): sendto_entry_handler,
        ('sendto', False): sendto_exit_handler,
        ('shutdown', True): shutdown_subcall_entry_handler,
        ('recvmsg', True): recvmsg_entry_handler,
        ('recvmsg', False): recvmsg_exit_handler,
        ('getsockname', True): getsockname_entry_handler,
        ('getsockname', False): getsockname_exit_handler,
        ('getpeername', True): getpeername_entry_handler
    }
    subcall_id = cint.peek_register(pid, cint.EBX)
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
        ebx = cint.peek_register(pid, cint.EBX)
        logging.debug('Socketcall id from EBX is: %s', ebx)
        socketcall_handler(syscall_id, syscall_object, entering, pid)
        return
    logging.debug('Checking syscall against execution')
    validate_syscall(orig_eax, syscall_object)
    ignore_list = [
        162,  # sys_nanosleep
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
        # These calls just get their return values checked ####
        # (9, True): check_return_value_entry_handler,
        # (9, False): check_return_value_exit_handler,
        # (195, True): check_return_value_entry_handler,
        # (195, False): check_return_value_exit_handler,
        (39, True): check_return_value_entry_handler,
        (39, False): check_return_value_exit_handler,
        (45, True): check_return_value_entry_handler,
        (45, False): check_return_value_exit_handler,
        (91, True): check_return_value_entry_handler,
        (91, False): check_return_value_exit_handler,
        # (125, True): check_return_value_entry_handler,
        # (125, False): check_return_value_exit_handler,
        # mmap2 calls are never replayed. Sometimes we must fix a file
        # descriptor  in position 4.
        (192, True): mmap2_entry_handler,
        (192, False): mmap2_exit_handler,
        (196, True): lstat64_entry_handler,
        (10, True): unlink_entry_handler,
        (10, False): check_return_value_exit_handler,
        (20, True): syscall_return_success_handler,
        (30, True): syscall_return_success_handler,
        (38, True): rename_entry_handler,
        (38, False): check_return_value_exit_handler,
        (15, True): syscall_return_success_handler,
        (78, True): gettimeofday_entry_handler,
        (13, True): time_entry_handler,
        (27, True): syscall_return_success_handler,
        (5, True): open_entry_handler,
        (5, False): open_exit_handler,
        (60, True): syscall_return_success_handler,
        (85, True): readlink_entry_handler,
        (94, True): fchmod_entry_handler,
        (94, False): check_return_value_entry_handler,
        (146, True): writev_entry_handler,
        (146, False): writev_exit_handler,
        (197, True): fstat64_entry_handler,
        (197, False): check_return_value_exit_handler,
        (122, True): uname_entry_handler,
        (183, True): getcwd_entry_handler,
        (140, True): llseek_entry_handler,
        (140, False): llseek_exit_handler,
        (42, True): pipe_entry_handler,
        # (43, True): times_entry_handler,
        # (10, True): syscall_return_success_handler,
        (33, True): syscall_return_success_handler,
        (199, True): syscall_return_success_handler,
        (200, True): syscall_return_success_handler,
        (201, True): syscall_return_success_handler,
        (202, True): syscall_return_success_handler,
        (4, True): write_entry_handler,
        (4, False): write_exit_handler,
        (3, True): read_entry_handler,
        (3, False): check_return_value_exit_handler,
        (6, True): close_entry_handler,
        (6, False): close_exit_handler,
        (168, True): poll_entry_handler,
        (54, True): ioctl_entry_handler,
        (195, True): stat64_entry_handler,
        (195, False): check_return_value_exit_handler,
        (142, True): select_entry_handler,
        (82, True): select_entry_handler,
        (221, True): fcntl64_entry_handler,
        (196, True): lstat64_entry_handler,
        (268, True): statfs64_entry_handler,
        (265, True): clock_gettime_entry_handler,
        (41, True): dup_entry_handler,
        (41, False): dup_exit_handler,
        (186, True): sigaltstack_entry_handler,
        (207, True): fchown_entry_handler,
        (207, False): check_return_value_entry_handler,
        (220, True): getdents64_entry_handler,
        (220, False): getdents64_exit_handler,
        (228, True): fsetxattr_entry_handler,
        (228, False): fsetxattr_exit_handler,
        (231, True): fgetxattr_entry_handler,
        (231, False): fgetxattr_exit_handler,
        (234, True): flistxattr_entry_handler,
        (234, False): flistxattr_entry_handler,
        (242, True): sched_getaffinity_entry_handler,
        (272, True): fadvise64_64_entry_handler,
        (272, False): check_return_value_exit_handler,
        (295, True): openat_entry_handler,
        (295, False): openat_exit_handler,
        (300, True): fstatat64_entry_handler,
        (300, False): check_return_value_exit_handler,
        (301, True): unlinkat_entry_handler,
        (301, False): check_return_value_exit_handler,
        (320, True): utimensat_entry_handler,
        (320, False): check_return_value_exit_handler,
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
    parser.add_argument('-k',
                        '--checker',
                        help='Specify a checker by Python constructor')
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
        cint.enable_debug_output(numeric_level)
    logging.debug('About to spawn child process')
    # TODO: HACK!
    checker = None
    if args.get('checker') is not None:
        checker = args['checker']
        logging.debug('Checker string: %s', checker)
        checker = eval('tracereplay.checker.' + checker)
    pid = os.fork()
    if pid == 0:
        cint.traceme()
        os.execvp(command[0], command)
    else:
        debug_printers = {
            5: open_entry_debug_printer,
            6: close_entry_debug_printer,
            3: read_entry_debug_printer,
            4: write_entry_debug_printer,
            10: unlink_entry_debug_printer,
            13: time_entry_debug_printer,
            33: access_entry_debug_printer,
            41: dup_entry_debug_printer,
            45: brk_entry_debug_printer,
            54: ioctl_entry_debug_printer,
            91: munmap_entry_debug_printer,
            102: socketcall_debug_printer,
            142: select_entry_debug_printer,
            174: rt_sigaction_entry_debug_printer,
            175: rt_sigprocmask_entry_debug_printer,
            192: mmap2_entry_debug_printer,
            195: stat64_entry_debug_printer,
            196: lstat64_entry_debug_printer,
            197: fstat64_entry_debug_printer,
            221: fcntl64_entry_debug_printer
        }
        t = Trace.Trace(trace)
        tracereplay.system_calls = t.syscalls
        logging.info('Parsed trace with %s syscalls', len(t.syscalls))
        logging.info('Entering syscall handling loop')
        while next_syscall():
            orig_eax = cint.peek_register(pid, cint.ORIG_EAX)
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
                advance_trace()
                cint.syscall(pid)
                continue
            if tracereplay.entering_syscall:
                syscall_object = advance_trace()
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

            if checker:
                logging.debug('Transitioning checker')
                checker.transition(syscall_object)
            logging.info('# of System Calls Handled: %d',
                         tracereplay.handled_syscalls)
            tracereplay.entering_syscall = not tracereplay.entering_syscall
            logging.debug('Requesting next syscall')
            cint.syscall(pid)
        if checker:
            logging.info('Exited with checker in accepting state: %s',
                         checker.is_accepting())
