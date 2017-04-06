from __future__ import print_function
import logging

from util import(validate_integer_argument,
                 should_replay_based_on_fd,
                 noop_current_syscall,
                 apply_return_conditions,
                 cint,
                 swap_trace_fd_to_execution_fd,
                 ReplayDeltaError,
                 extract_socketcall_parameters,
                 cleanup_quotes)


# Bare minimum implementation
def recvmsg_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering recvmsg entry handler')
    p = cint.peek_register(pid, cint.ECX)
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
    p = cint.peek_register(pid, cint.ECX)
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
        data = cleanup_quotes(syscall_object.args[1].value)
        data = data.decode('string_escape')
        cint.populate_char_buffer(pid,
                                  buffer_address,
                                  data)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)
        logging.info('Not replaying this system call')


def recvfrom_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = cint.peek_register(pid, cint.ECX)
    params = extract_socketcall_parameters(pid, p, 6)
    validate_integer_argument(pid, syscall_object, 0, 0, params)
    validate_integer_argument(pid, syscall_object, 2, 2, params)
    # We don't check params[1] because it is the address of an empty buffer
    # We don't check params[3] because it is a flags field
    # We don't check params[4] because it is the address of an empty buffer
    # We don't check params[5] because it is the address of a length
    data_buf_addr_e = params[1]
    data_buf_length_e = params[2]
    sockaddr_addr_e = params[4]
    sockaddr_length_addr_e = params[5]

    fd_t = syscall_object.args[0].value
    data = syscall_object.args[1].value
    data = cleanup_quotes(data)
    data = data.decode('string_escape')
    sockfields = syscall_object.args[4].value
    port = int(sockfields[1].value)
    ip = sockfields[2].value
    sockaddr_length_t = int(syscall_object.args[5].value.strip('[]'))

    ret_val = int(syscall_object.ret[0])

    # Decide if we want to replay this system call
    if should_replay_based_on_fd(fd_t):
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if len(data) != ret_val:
            raise ReplayDeltaError('Decoded bytes length ({}) does not equal '
                                   'return value from trace ({})'
                                   .format(len(data), ret_val))
        cint.populate_char_buffer(pid, data_buf_addr_e, data)
        cint.populate_af_inet_sockaddr(pid,
                                       sockaddr_addr_e,
                                       port,
                                       ip,
                                       sockaddr_length_addr_e,
                                       sockaddr_length_t)
        buf = cint.copy_address_range(pid,
                                      data_buf_addr_e,
                                      data_buf_addr_e + data_buf_length_e)
        if buf[:ret_val] != data:
            raise ReplayDeltaError('Data copied by read() handler doesn\'t '
                                   'match after copy')
        apply_return_conditions(pid, syscall_object)
        print(cint.peek_register(pid, cint.EAX))
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)
