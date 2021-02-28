import logging
from util import *


def timer_create_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_create entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        # only SIGEV_NONE is supported as other sigevents can't be replicated as of now
        sigev_type = syscall_object.args[3].value.strip()
        logging.debug("Sigevent type: " + str(sigev_type))

        if sigev_type != 'SIGEV_NONE':
            raise NotImplementedError("Sigevent type %s is not supported for timer_create" % (sigev_type))
        else:
            # addr
            addr = cint.peek_register(pid, cint.EDX)
            logging.debug('timerid address: %x', addr)

            # timerid
            timerid = int(syscall_object.args[-1].value.strip('{}'))
            logging.debug(str(timerid))

            cint.populate_timer_t_structure(pid, addr, timerid);

            noop_current_syscall(pid)
            apply_return_conditions(pid, syscall_object)


def timer_create_exit_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_create exit handler")
    logging.debug("Nothing to do here")


def timer_extract_and_populate_itimerspec(syscall_object, pid, addr, start_index):
    logging.debug('Itimerspec Address: %x', addr)
    logging.debug('Extracting itimerspec')

    i = start_index
    interval_seconds = int(syscall_object.args[i].value.split("{")[2].strip())
    interval_nanoseconds = int(syscall_object.args[i+1].value.strip('{}'))        
    logging.debug('Interval Seconds: %d', interval_seconds)
    logging.debug('Interval Nanoseconds: %d', interval_nanoseconds)
    
    value_seconds = int(syscall_object.args[i+2].value.split("{")[1].strip())
    value_nanoseconds = int(syscall_object.args[i+3].value.strip('{}'))
    logging.debug('Value Seconds: %d', value_seconds)
    logging.debug('Value Nanoseconds: %d', value_nanoseconds)
    
    logging.debug('Populating itimerspec structure')
    cint.populate_itimerspec_structure(pid, addr,
                                       interval_seconds, interval_nanoseconds,
                                       value_seconds, value_nanoseconds)


def timer_settime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_settime entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug(str(syscall_object.args[-1]))
        
        old_value_present = syscall_object.args[-1].value != 'NULL'
        if old_value_present:
            logging.debug("Old value present, have to copy it into memory")

            addr = cint.peek_register(pid, cint.ESI)
            logging.debug('old_value address: %x', addr)

            itimerspec_starting_index = 6;
            timer_extract_and_populate_itimerspec(syscall_object, pid, addr, itimerspec_starting_index)
        
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def timer_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_gettime entry handler")
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        logging.debug('Got successful timer_gettime call')
        logging.debug('Replaying this system call')

        # these should be the same probably?
        timer_id_from_trace = int(syscall_object.args[0].value[0].strip('0x'))
        timer_id_from_execution = int(cint.peek_register(pid, cint.EBX))

        if timer_id_from_trace != timer_id_from_execution:
            raise ReplayDeltaError("Timer id ({}) from execution "
                                    "differs from trace ({})"
                                   .format(timer_id_from_execution, timer_id_from_trace))

        addr = cint.peek_register(pid, cint.ECX)
        itimerspec_starting_index = 1;
        timer_extract_and_populate_itimerspec(syscall_object, pid, addr, itimerspec_starting_index)
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def timer_delete_entry_handler(syscall_id, syscall_object, pid):
    logging.debug("Entering the timer_delete entry handler")

    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def time_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering time entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        addr = cint.peek_register(pid, cint.EBX)
        noop_current_syscall(pid)
        logging.debug('Got successful time call')
        t = int(syscall_object.ret[0])
        logging.debug('time: %d', t)
        logging.debug('addr: %d', addr)
        if syscall_object.args[0].value != 'NULL':
            cint.populate_unsigned_int(pid, addr, t)
        apply_return_conditions(pid, syscall_object)


def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering gettimeofday entry handler')
    if syscall_object.ret[0] == -1:
        raise NotImplementedError('Unsuccessful calls not implemented')
    else:
        noop_current_syscall(pid)
        if syscall_object.args[2].value != 'NULL':
            raise NotImplementedError('time zones not implemented')
        addr = cint.peek_register(pid, cint.EBX)
        seconds = int(syscall_object.args[0].value.strip('{}'))
        microseconds = int(syscall_object.args[1].value.strip('{}'))
        logging.debug('Address: %x', addr)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Microseconds: %d', microseconds)
        logging.debug('Populating timeval structure')
        cint.populate_timeval_structure(pid, addr,
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
        clock_type_from_execution = cint.peek_register(pid,
                                                              cint.EBX)
        # The first arg from execution must be CLOCK_MONOTONIC
        # The first arg from the trace must be CLOCK_MONOTONIC
        if clock_type_from_trace == 'CLOCK_MONOTONIC':
            if clock_type_from_execution != cint.CLOCK_MONOTONIC:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        if clock_type_from_trace == 'CLOCK_PROCESS_CPUTIME_ID':
            if clock_type_from_execution != cint.CLOCK_PROCESS_CPUTIME_ID:
                raise ReplayDeltaError('Clock type ({}) from execution '
                                       'differs from trace'
                                       .format(clock_type_from_execution))
        seconds = int(syscall_object.args[1].value.strip('{}'))
        nanoseconds = int(syscall_object.args[2].value.strip('{}'))
        addr = cint.peek_register(pid, cint.ECX)
        logging.debug('Seconds: %d', seconds)
        logging.debug('Nanoseconds: %d', nanoseconds)
        logging.debug('Address: %x', addr)
        logging.debug('Populating timespec strucutre')
        cint.populate_timespec_structure(pid, addr,
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
        timespec0_addr = cint.peek_register(pid, cint.EDX)
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
        cint.populate_timespec_structure(pid,
                                                timespec0_addr,
                                                timespec0_seconds,
                                                timespec0_nseconds)
        cint.populate_timespec_structure(pid,
                                                timespec1_addr,
                                                timespec1_seconds,
                                                timespec1_nseconds)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)
        logging.debug('Not replaying this system call')



def time_entry_debug_printer(pid, orig_eax, syscall_object):
    param = cint.peek_register(pid, cint.EBX)
    if param == 0:
        logging.debug('Time called with a NULL time_t')
    else:
        logging.debug('time_t addr: %d', param)
