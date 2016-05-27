from tracereplay_python import *
import logging


# Bare minimum implementation
def recvmsg_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering recvmsg entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_execution = int(params[0])
    fd_from_trace = int(syscall_object.args[0].value)
    logging.debug('File descriptor from execution: %d', fd_from_execution)
    logging.debug('File descriptor from trace: %d', fd_from_trace)
    if fd_from_execution != fd_from_trace:
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd_from_execution, fd_from_trace))
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        raise NotImplementedError('recvmsg entry handler not '
                                  'implemented for tracked sockets')
    else:
        logging.debug('Not replaying this system call')


def recvmsg_exit_handler(syscall_id, syscall_object, pid):
    pass


def recv_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    # Pull out everything we can check
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # We don't check params[1] because it is the address of an empty buffer
    length = params[2]
    length_from_trace = syscall_object.args[2].value
    # We don't check params[3] because it is a flags field
    # Check to make everything is the same
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    if length != int(length_from_trace):
        raise Exception('Length from execution ({}) does not match '
                        'length from trace ({})'
                        .format(length, length_from_trace))
    # Decide if we want to replay this system call
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if params[0] not in tracereplay.FILE_DESCRIPTORS:
            raise Exception('Tried to recv from non-existant file descriptor')
        buffer_address = params[1]
        buffer_size = syscall_object.ret[0]
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = data.decode('string_escape')
        tracereplay.populate_char_buffer(pid,
                                         buffer_address,
                                         data,
                                         buffer_size)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')


def recvfrom_subcall_entry_handler(syscall_id, syscall_object, pid):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 6)
    # Pull out everything we can check
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    # We don't check params[1] because it is the address of an empty buffer
    buffer_length = int(params[2])
    buffer_length_from_trace = int(syscall_object.args[2].value)
    logging.debug('Buffer length: %d', buffer_length)
    logging.debug('Buffer length from trace: %d', buffer_length_from_trace)
    if buffer_length != buffer_length_from_trace:
        raise ReplayDeltaError('Buffer length from execution ({}) differs from '
                               'buffer length from trace ({})'
                               .format(buffer_length,
                                       buffer_length_from_trace))
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
    if fd != int(fd_from_trace):
        raise Exception('File descriptor from execution ({}) does not match '
                        'file descriptor from trace ({})'
                        .format(fd, fd_from_trace))
    # if buffer_length != int(buffer_length_from_trace):
    #     raise Exception('Length from execution ({}) does not match '
    #                     'length from trace ({})'
    #                     .format(buffer_length, buffer_length_from_trace))
    # Decide if we want to replay this system call
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if params[0] not in tracereplay.FILE_DESCRIPTORS:
            raise Exception('Tried to recvfrom from non-existant file '
                            'descriptor')
        buffer_address = params[1]
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = data.decode('string_escape')
        logging.debug('Data length %d', len(data))
        tracereplay.copy_bytes_into_child_process(pid, buffer_address, data)
        tracereplay.populate_af_inet_sockaddr(pid,
                                              addr,
                                              port,
                                              ip,
                                              length_addr,
                                              int(length))
        apply_return_conditions(pid, syscall_object)
        print(tracereplay.peek_register(pid, tracereplay.EAX))
    else:
        logging.info('Not replaying this system call')
