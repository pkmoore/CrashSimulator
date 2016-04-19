import logging
import os
import sys
import signal
import tracereplay

def time_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering time entry handler')
    _exit(pid)

def clock_gettime_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering clock_gettime entry handler')
    if syscall_object.ret[0] == -1:
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

def gettimeofday_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering time entry handler')
    _exit(pid)

def _exit(pid):
    os.kill(pid, signal.SIGKILL)
    sys.exit(1)

# This function leaves the child process in a state of waiting at the point just
# before execution returns to user code.
def noop_current_syscall(pid):
    logging.debug('Nooping the current system call in pid: %s', pid)
    tracereplay.poke_register(pid, tracereplay.ORIG_EAX, 20)
    tracereplay.syscall(pid)
    next_syscall()
    skipping = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
    if skipping != 20:
        os.kill(pid, signal.SIGKILL)
        raise Exception('Nooping did not result in getpid exit. Got {}'.format(skipping))
    global entering_syscall
    entering_syscall = False

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

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
                os.kill(pid, signal.SIGKILL)
                raise Exception('Couldn\'t get integer form of return value!')
    logging.debug('Cleaned up value %s', ret_val)
    return ret_val
