import logging

from util import *


# Like the subcall return success handler, this handler just no-ops out a call
# and returns whatever it returned from the trace. Used by ioctl and stat64
def syscall_return_success_handler(syscall_id, syscall_object, pid):
    logging.debug('Using default "return success" handler')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def check_return_value_entry_handler(syscall_id, syscall_object, pid):
    pass


def check_return_value_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering check_return_value exit handler')
    ret_from_execution = cint.peek_register(pid, cint.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    logging.debug('Return value from execution %x', ret_from_execution)
    logging.debug('Return value from trace %x', ret_from_trace)
    if ret_from_execution < 0:
        ret_from_execution = ret_from_execution & 0xffffffff
    if ret_from_execution != ret_from_trace:
        raise Exception('Return value from execution ({}, {:02x}) differs '
                        'from return value from trace ({}, {:02x})'
                        .format(ret_from_execution,
                                ret_from_execution,
                                ret_from_trace,
                                ret_from_trace))
