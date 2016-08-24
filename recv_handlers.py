from tracereplay_python import *
import logging


# Bare minimum implementation
def recvmsg_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering recvmsg entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params)
    if should_replay_based_on_fd(fd_from_trace):
        raise NotImplementedError('recvmsg entry handler not '
                                  'implemented for tracked sockets')
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)


def recvmsg_exit_handler(syscall_id, syscall_object, pid):
    pass


def recv_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    # Pull out everything we can check
    fd_from_trace = syscall_object.args[0].value
    # We don't check params[1] because it is the address of an empty buffer
    # We don't check params[3] because it is a flags field
    # Check to make everything is the same
    validate_integer_argument(pid, syscall_object, 0, 0, params)
    validate_integer_argument(pid, syscall_object, 2, 2, params)
    # Decide if we want to replay this system call
    if should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        buffer_address = params[1]
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = data.decode('string_escape')
        tracereplay.populate_char_buffer(pid,
                                         buffer_address,
                                         data)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)
        logging.info('Not replaying this system call')


def recvfrom_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 6)
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params)
    validate_integer_argument(pid, syscall_object, 2, 2, params)
    # We don't check params[1] because it is the address of an empty buffer
    # We don't check params[3] because it is a flags field
    # We don't check params[4] because it is the address of an empty buffer
    # We don't check params[5] because it is the address of a length
    addr = params[4]
    length_addr = params[5]
    length = syscall_object.args[5].value.strip('[]')
    sockfields = syscall_object.args[4].value
    port = int(sockfields[1].value)
    ip = sockfields[2].value
    # Check to make everything is the same
    # if buffer_length != int(buffer_length_from_trace):
    #     raise Exception('Length from execution ({}) does not match '
    #                     'length from trace ({})'
    #                     .format(buffer_length, buffer_length_from_trace))
    # Decide if we want to replay this system call
    if should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if params[0] not in tracereplay.REPLAY_FILE_DESCRIPTORS:
            raise Exception('Tried to recvfrom from non-existant file '
                            'descriptor')
        buffer_address = params[1]
        ret_val = int(syscall_object.ret[0])
        data = syscall_object.args[1].value
        data = cleanup_quotes(data)
        data = data.decode('string_escape')
        if len(data) != ret_val:
            raise ReplayDeltaError('Decoded bytes length ({}) does not equal '
                                   'return value from trace ({})'
                                   .format(len(data), ret_val))
        tracereplay.populate_char_buffer(pid, buffer_address, data)
        tracereplay.populate_af_inet_sockaddr(pid,
                                              addr,
                                              port,
                                              ip,
                                              length_addr,
                                              int(length))
        buf = tracereplay.copy_address_range(pid,
                                             buffer_address,
                                             buffer_address + ret_val)
        if buf != data:
            raise ReplayDeltaError('Data copied by read() handler doesn\'t '
                                   'match after copy')
        apply_return_conditions(pid, syscall_object)
        print(tracereplay.peek_register(pid, tracereplay.EAX))
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)
