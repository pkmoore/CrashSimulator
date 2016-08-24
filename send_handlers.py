from tracereplay_python import *
import logging


def send_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering send entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    validate_integer_argument(pid, syscall_object, 2, 2, params=params)
    trace_fd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(trace_fd):
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)


def send_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering send exit handler')
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    if ret_val_from_execution != ret_val_from_trace:
        raise ReplayDeltaError('Return value from execution ({}) differs '
                               'from return value from trace ({})'
                               .format(ret_val_from_execution,
                                       ret_val_from_trace))


def sendto_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sendto entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 3)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    validate_integer_argument(pid, syscall_object, 2, 2, params=params)
    if should_replay_based_on_fd(fd_from_trace):
        logging.debug('Replaying this system call')
        subcall_return_success_handler(syscall_id, syscall_object, pid)
    else:
        logging.debug('Not replaying this call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)


def sendto_exit_handler(syscall_id, syscall_object, pid):
    pass


def sendmmsg_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sendmmsg entry handler')
    sockfd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0)
    if should_replay_based_on_fd(sockfd_from_trace):
        logging.debug('Replaying this sytem call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got successful sendmmsg call')
            number_of_messages = syscall_object.ret[0]
            if syscall_id == 102:
                p = tracereplay.peek_register(pid, tracreplay.ECX)
                params = extract_socketcall_parameters(pid, p, 4)
                addr = params[1]
            else:
                addr = tracereplay.peek_register(pid, tracereplay.ECX)
            logging.debug('Number of messages %d', number_of_messages)
            logging.debug('Address of buffer %x', addr & 0xffffffff)
            lengths = [int(syscall_object.args[x].value.rstrip('}'))
                       for x in range(6, (number_of_messages * 6) + 1, 6)]
            logging.debug('Lengths: %s', lengths)
            tracereplay.write_sendmmsg_lengths(pid,
                                               addr,
                                               number_of_messages,
                                               lengths)
        else:
            logging.debug('Got unsuccessful sendmmsg call')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


def sendmmsg_exit_handler(syscall_id, syscall_object, pid):
    pass
