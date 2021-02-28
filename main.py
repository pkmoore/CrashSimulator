from __future__ import print_function

import ConfigParser
import argparse
import signal
import sys
import os
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
    ''' Validate the subcall (NOT SYSCALL!) id of the socket subcall against
    the subcall name we expect based on the current system call object.  Then,
    hand off responsibility to the appropriate subcall handler.

    TODO: rename to handle_socketcall and correct references as needed

    '''
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
    # The subcall id of the socket subcall is located in the EBX register
    # according to our Linux's convention.
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
    ''' Validate the id of the system call against the name of the system call
    we are expecting based on the current system call object.  Then hand off
    responsiblity to the appropriate subcall handler.
    TODO: cosmetic - Reorder handler entrys numerically
    

    '''
    logging.debug('Handling syscall')
    # If we are entering a system call, update the number of system calls we
    # have handled
    if entering:
        tracereplay.handled_syscalls += 1
    # System call id 102 corresponds to 'socket subcall'.  This system call is
    # the entry point for code calls the appropriate socketf code based on the
    # subcall id in EBX.
    if syscall_id == 102:
        logging.debug('This is a socket subcall')
        # TODO: delete this logging
        ebx = cint.peek_register(pid, cint.EBX)
        logging.debug('Socketcall id from EBX is: %s', ebx)

        # Hand off to code that deals with socket calls and return once that is
        # complete.  Exceptions will be thrown if something is unsuccessful
        # that end.  Return immediately after because we don't want our system
        # call handler code double-handling the already handled socket subcall
        socketcall_handler(syscall_id, syscall_object, entering, pid)
        return
    logging.debug('Checking syscall against execution')
    validate_syscall(orig_eax, syscall_object)
    # We ignore these system calls because they have to do with aspecs of
    # execution that we don't want to try to replay and, at the same time,
    # don't have interesting information that we want to validate with a
    # handler.
    ignore_list = [
        77,   # sys_getrusage
        162,  # sys_nanosleep
        125,  # sys_mprotect
        175,  # sys_rt_sigprocmask
        116,  # sys_sysinfo
        119,  # sys_sigreturn
        126,  # sys_sigprocmask
        186,  # sys_sigaltstack
        266,  # set_clock_getres
        240,  # sys_futex
        242,  # sys_sched_getaffinity
        243,  # sys_set_thread_area
        311,  # sys_set_robust_list
        340,  # sys_prlimit64
        191,  # !!!!!!!!! sys_getrlimit
        ]
    handlers = {
        (8, True): creat_entry_handler,
        (8, False): check_return_value_exit_handler,
        # These calls just get their return values checked ####
        # (9, True): check_return_value_entry_handler,
        # (9, False): check_return_value_exit_handler,
        (12, True): syscall_return_success_handler,
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
        (93, True): ftruncate_entry_handler,
        (93, False): ftruncate_exit_handler,
        (94, True): fchmod_entry_handler,
        (94, False): check_return_value_entry_handler,
        (145, True): readv_entry_handler,
        (145, False): check_return_value_exit_handler,
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
        (54, False): ioctl_exit_handler,
        (195, True): stat64_entry_handler,
        (195, False): check_return_value_exit_handler,
        (141, True): getdents_entry_handler,
        (142, False): getdents_exit_handler,
        (142, True): select_entry_handler,
        (82, True): select_entry_handler,
        (221, True): fcntl64_entry_handler,
        (196, True): lstat64_entry_handler,
        (268, True): statfs64_entry_handler,
        (265, True): clock_gettime_entry_handler,
        (41, True): dup_entry_handler,
        (41, False): dup_exit_handler,
        (150, True): syscall_return_success_handler,
        (174, True): rt_sigaction_entry_handler,
        (186, True): sigaltstack_entry_handler,
        (194, True): ftruncate64_entry_handler,
        (194, False): ftruncate64_entry_handler,
        (207, True): fchown_entry_handler,
        (207, False): check_return_value_entry_handler,
        (209, True): getresuid_entry_handler,
        (211, True): getresgid_entry_handler,
        (220, True): getdents64_entry_handler,
        (220, False): getdents64_exit_handler,
        (228, True): fsetxattr_entry_handler,
        (228, False): fsetxattr_exit_handler,
        (231, True): fgetxattr_entry_handler,
        (231, False): fgetxattr_exit_handler,
        (234, True): flistxattr_entry_handler,
        (234, False): flistxattr_entry_handler,
        (242, True): sched_getaffinity_entry_handler,
        (243, True): syscall_return_success_handler,
        (258, True): set_tid_address_entry_handler,
        (258, False): set_tid_address_exit_handler,
        (259, True): timer_create_entry_handler,
        (259, False): timer_create_exit_handler,
        (260, True): timer_settime_entry_handler,
        (261, True): timer_gettime_entry_handler,
        (263, True): timer_delete_entry_handler,
        (265, True): clock_gettime_entry_handler,        
        (271, True): syscall_return_success_handler,
        (272, True): fadvise64_64_entry_handler,
        (272, False): check_return_value_exit_handler,
        (295, True): openat_entry_handler,
        (295, False): openat_exit_handler,
        (300, True): fstatat64_entry_handler,
        (300, False): check_return_value_exit_handler,
        (301, True): unlinkat_entry_handler,
        (301, False): check_return_value_exit_handler,
        (311, True): syscall_return_success_handler,
        (320, True): utimensat_entry_handler,
        (320, False): check_return_value_exit_handler,
        (328, True): eventfd2_entry_handler,
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
    parser.add_argument('-m',
                        '--mutator',
                        help='Specify a mutator by python constructor')
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
        command = args['command']
        trace = args['trace']
    # At this point we're not using switches so we MUST use a config file
    elif args.get('config_file') is not None:
        config_file = args['config_file']
        config = ConfigParser.ConfigParser()
        config.readfp(open(config_file))
        command = config.get('Replay', 'command')
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
    mutator = None
    if args.get('mutator'):
        mutator = args['mutator']
        logging.debug('Mutator string: $s', mutator)
        mutator = eval('tracereplay.mutator.' + mutator)
    # Evaluate what is hopefully a list literal into an actual list we can use
    command = eval(command)

    # At this point, we have parsed our arguments and are ready to start the
    # replay process.  We must fork a new process in which to launch the target
    # process.
    pid = os.fork()
    # If we are the child process (i.e. pid returned form fork() == 0)
    if pid == 0:
        # Request that some other process trace the current process
        cint.traceme()
        # Replace the image old image of the process (our code) with the image
        # of the target application and execute it (with the provided
        # parameters)
        os.execvp(command[0], command)
    # Else, we are not the child process and should configure ourselves to
    # begin monitoring with ptrace in order to perform the replay process
    else:
        # This definition needs to be elsewhere to clarify this code.  It's
        # here right now mostly out of laziness.
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
            221: fcntl64_entry_debug_printer,
        }
        # Open our trace (specified as either a command line argument with -t
        # or as specified in a replay config file.  Then pass it to the
        # posix-omni-parser so that it can turned into a set of objects.
        if mutator:
            logging.debug('Mutating trace')
            trace = mutator.mutate_trace(trace)
            logging.debug('Mutated trace at: %s', trace)
        t = Trace.Trace(trace)
        tracereplay.system_calls = t.syscalls
        logging.info('Parsed trace with %s syscalls', len(t.syscalls))
        logging.info('Entering syscall handling loop')

        # Loop until we are no longer receiving syscall notifications from our
        # ptrace session with the child process.
        while next_syscall():
            # Get the system call id of the current system call.  Convention in
            # our flavor of Linux is for this to be passed in the EAX
            # register (ORIG_EAX, in ptrace terms).  Ptrace does not inform us
            # of whether the current system call action we have been notified
            # of is an entry or exit so we operate on the assumption that the
            # first notification we receive is an entry, the next is an exit,
            # the next is an entry etc.
            orig_eax = cint.peek_register(pid, cint.ORIG_EAX)
            logging.info('===')
            logging.info('Advanced to next system call')
            logging.info('System call id from execution: %d', orig_eax)
            logging.info('Looked up system call name: %s', SYSCALLS[orig_eax])
            logging.info('This is a system call %s',
                         'entry' if tracereplay.entering_syscall else 'exit')
            # This if statement is an ugly hack.  We skip these system calls
            # out of sequence because they do not result in a corresponding
            # 'system call exit' notification from ptrace meaning they throw
            # off the pattern of 'entry', 'exit', 'entry', 'exit'... that we
            # rely on for determining whether the ptrace message we have
            # received is a system call entry or exit.
            if SYSCALLS[orig_eax] == 'sys_exit_group' or \
               SYSCALLS[orig_eax] == 'sys_execve' or \
               SYSCALLS[orig_eax] == 'sys_exit':
                logging.debug('Ignoring syscall')
                advance_trace()
                cint.syscall(pid)
                continue
            # Check the flip-flip flag to determine whether we are entering a
            # system call or exiting one.
            if tracereplay.entering_syscall:
                # If we're entering one, we need to get the next system call
                # object from our list of objects.
                syscall_object = advance_trace()
                logging.info('System call name from trace: %s',
                             syscall_object.name)
                logging.debug('System call object contents:\n%s',
                              syscall_object)
            # Try to handle the system call by first validating that the system
            # call id we read from EAX corresponds with the system call name
            # from the trace (i.e. the application is making system call X,
            # ensure that we are expecting system call X at this point based on
            # the trace).  Then we hand control (and the system call object
            # from the trace) off to the appropriate handler function that
            # deals with the specifics of the particular system call.
            try:
                handle_syscall(orig_eax, syscall_object,
                               tracereplay.entering_syscall,
                               pid)
            except:
                # Replay failed for some reason while trying to handle this
                # system call.  Print out relevant information including
                # informatin gathered by a system call specific 'debug printer'
                # if one has been written
                traceback.print_exc()
                try:
                    debug_printers[orig_eax](pid, orig_eax, syscall_object)
                except KeyError:
                    logging.warning('This system call ({}) has no debug '
                                    'printer'.format(orig_eax))
                # Replay has failed, so kill the child process.  We've printed
                # all the useful information we have available so exit our own
                # process as well.
                os.kill(pid, signal.SIGKILL)
                sys.exit(1)

            # We have successfully handled the system call.  If we are running
            # with a checker, pass the system call object to the checker so it
            # can advance its internal state appropriately
            if checker:
                logging.debug('Transitioning checker')
                checker.transition(syscall_object)
            logging.info('# of System Calls Handled: %d',
                         tracereplay.handled_syscalls)

            # Flip the flip-flop flag that tracks whether we are the next
            # notification we receive is for a system call entry or exit
            tracereplay.entering_syscall = not tracereplay.entering_syscall
            logging.debug('Requesting next syscall')

            # Allow the child process to execute until it tries to enter or
            # exit another system call.
            cint.syscall(pid)

        # We have successfully completed our replay execution, did the checker
        # we specified exit in an accepting state?
        if checker:
            logging.info('Exited with checker in accepting state: %s',
                         checker.is_accepting())
        if mutator:
            os.remove(trace)
