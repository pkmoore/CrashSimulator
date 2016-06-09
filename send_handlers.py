from tracereplay_python import *
import logging


def sendto_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sendto entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_execution = int(params[0])
    fd_from_trace = int(syscall_object.args[0].value)
    logging.debug('File descriptor from execution: %d', fd_from_execution)
    logging.debug('File descriptor from trace: %d', fd_from_trace)
    if fd_from_execution != fd_from_trace:
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'does not match file descriptor from trace ({})'
                               .format(fd_from_execution, fd_from_trace))
    if fd_from_trace in tracereplay.REPLAY_FILE_DESCRIPTORS:
        logging.debug('Replaying this system call')
        subcall_return_success_handler(syscall_id, syscall_object, pid)
    else:
        logging.debug('Not replaying this call')


def sendto_exit_handler(syscall_id, syscall_object, pid):
    pass


def sendmmsg_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sendmmsg entry handler')
    sockfd_from_execution = tracereplay.peek_register(pid, tracereplay.EBX)
    sockfd_from_trace = syscall_object.args[0].value
    logging.debug('Socket file descriptor from execution %s',
                  sockfd_from_execution)
    logging.debug('Socket file descriptor from trace %s', sockfd_from_trace)
    if sockfd_from_trace != sockfd_from_execution:
        raise Exception('File descriptor from execution ({}) '
                        'differs from file descriptor from trace ({})'
                        .format(sockfd_from_execution,
                                sockfd_from_trace))
    if sockfd_from_trace in tracereplay.REPLAY_FILE_DESCRIPTORS:
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


def sendmmsg_exit_handler(syscall_id, syscall_object, pid):
    pass
