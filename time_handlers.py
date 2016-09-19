from tracereplay_python import *
import logging


def time_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering time entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        variable_from_trace = syscall_object.args[0].value
        logging.debug('Got successful time call')
        logging.debug(variable_from_trace)
        if variable_from_trace != 'NULL':
            raise NotImplementedError('time calls with out parameter not '
                                      'supported')
        t = int(syscall_object.ret[0])
        logging.debug('time: %d', t)
        apply_return_conditions(pid, syscall_object)


def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering gettimeofday entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        if syscall_object.args[2].value != 'NULL':
            raise NotImplementedError('time zones not implemented')
        addr = tracereplay.peek_register(pid, tracereplay.EBX)
        seconds = int(syscall_object.args[0].value.strip('{}'))
        microseconds = int(syscall_object.args[1].value.strip('{}'))
        logging.debug('Address: %x', addr)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Microseconds: %d', microseconds)
        logging.debug('Populating timeval structure')
        tracereplay.populate_timeval_structure(pid, addr,
                                               seconds, microseconds)
        apply_return_conditions(pid, syscall_object)


def clock_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering clock_gettime entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug('Got successful clock_gettime call')
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        clock_type_from_trace = syscall_object.args[0].value
        clock_type_from_execution = tracereplay.peek_register(pid,
                                                              tracereplay.EBX)
        # The first arg from execution must be CLOCK_MONOTONIC
        # The first arg from the trace must be CLOCK_MONOTONIC
        if clock_type_from_trace == 'CLOCK_MONOTONIC':
            if clock_type_from_execution != tracereplay.CLOCK_MONOTONIC:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        if clock_type_from_trace == 'CLOCK_PROCESS_CPUTIME_ID':
            if clock_type_from_execution != tracereplay.CLOCK_PROCESS_CPUTIME_ID:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        seconds = int(syscall_object.args[1].value.strip('{}'))
        nanoseconds = int(syscall_object.args[2].value.strip('{}'))
        addr = tracereplay.peek_register(pid, tracereplay.ECX)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Nanoseconds: %d', nanoseconds)
        logging.debug('Address: %x', addr)
        logging.debug('Populating timespec strucutre')
        tracereplay.populate_timespec_structure(pid, addr,
                                                seconds, nanoseconds)
        apply_return_conditions(pid, syscall_object)


def times_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering times entry handler')
    if syscall_object.args[0].value != 'NULL':
        raise NotImplementedError('Calls to times() with an out structure are '
                                  'not supported')
    logging.debug('Replaying system call')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def utimensat_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering utimensat entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        noop_current_syscall(pid)
        logging.debug('Replaying this system call')
        timespec0_addr = tracereplay.peek_register(pid, tracereplay.EDX)
        timespec1_addr = timespec0_addr + 4
        logging.debug('Timespec 0 addr: %d', timespec0_addr)
        logging.debug('Timespec 1 addr: %d', timespec1_addr)
        timespec0_seconds = syscall_object.args[2].value
        timespec0_seconds = int(timespec0_seconds.strip('{}'))
        timespec0_nseconds = syscall_object.args[3].value[0]
        timespec0_nseconds = int(timespec0_nseconds.rstrip('}'))
        logging.debug('Timespec0 seconds: %d nseconds: %d',
                      timespec0_seconds,
                      timespec0_nseconds)
        timespec1_seconds = syscall_object.args[4].value
        timespec1_seconds = int(timespec1_seconds.strip('{}'))
        timespec1_nseconds = syscall_object.args[5].value
        timespec1_nseconds = int(timespec1_nseconds.rstrip('}'))
        logging.debug('Timespec1 seconds: %d nseconds: %d',
                      timespec1_seconds,
                      timespec1_nseconds)
        tracereplay.populate_timespec_structure(pid,
                                                timespec0_addr,
                                                timespec0_seconds,
                                                timespec0_nseconds)
        tracereplay.populate_timespec_structure(pid,
                                                timespec1_addr,
                                                timespec1_seconds,
                                                timespec1_nseconds)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')



def time_entry_debug_printer(pid, orig_eax, syscall_object):
    param = tracereplay.peek_register(pid, tracereplay.EBX)
    if param == 0:
        logging.debug('Time called with a NULL time_t')
    else:
        logging.debug('time_t addr: %d', param)
