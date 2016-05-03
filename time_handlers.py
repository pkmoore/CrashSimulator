from tracereplay_python import *
import os
import logging
import signal

def time_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering time entry handler')
    if syscall_object.ret[0] == -1:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        variable_from_trace = syscall_object.args[0].value
        logging.debug('Got successful time call')
        logging.debug(variable_from_trace)
        if variable_from_trace != 'NULL':
            os.kill(pid, signal.SIGKILL)
            raise NotImplementedError('time calls with out parameter not '
                                      'supported')
        t = int(syscall_object.ret[0])
        logging.debug('time: %d', t)
        apply_return_conditions(pid, syscall_object)

def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering gettimeofday entry handler')
    if syscall_object.ret[0] == -1:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        if syscall_object.args[2].value != 'NULL':
            os.kill(pid, signal.SIGKILL)
            raise NotImplementedError('time zones not implemented')
        addr = tracereplay.peek_register(pid, tracereplay.EBX)
        seconds = int(syscall_object.args[0].value.strip('{}'))
        microseconds = int(syscall_object.args[1].value.strip('{}'))
        logging.debug('Address: %x', addr)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Microseconds: %d', microseconds)
        logging.debug('Populating timeval structure')
        tracereplay.populate_timeval_structure(pid, addr, seconds, microseconds)
        apply_return_conditions(pid, syscall_object)

def clock_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering clock_gettime entry handler')
    if syscall_object.ret[0] == -1:
        os.kill(pid, signal.SIGKILL)
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug('Got successful clock_gettime call')
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        clock_type_from_trace = syscall_object.args[0].value
        clock_type_from_execution = tracereplay.peek_register(pid, tracereplay.EBX)
        #The first arg from execution must be CLOCK_MONOTONIC
        #The first arg from the trace must be CLOCK_MONOTONIC
        if syscall_object.args[0].value[0] != "CLOCK_MONOTONIC":
            raise NotImplementedError('Clock type ({}) from trace is not '
                                    'CLOCK_MONOTONIC' \
                                    .format(clock_type_from_trace))
        if clock_type_from_execution != tracereplay.CLOCK_MONOTONIC:
            raise NotImplementedError('Clock type ({}) from execution is not '
                                    'CLOCK_MONOTONIC' \
                                    .format(clock_type_from_execution))
        seconds = int(syscall_object.args[1].value.strip('{}'))
        nanoseconds = int(syscall_object.args[2].value.strip('{}'))
        addr = tracereplay.peek_register(pid, tracereplay.ECX)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Nanoseconds: %d', nanoseconds)
        logging.debug('Address: %x', addr)
        logging.debug('Populating timespec strucutre')
        tracereplay.populate_timespec_structure(pid, addr, seconds, nanoseconds)
        apply_return_conditions(pid, syscall_object)
