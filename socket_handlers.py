from tracereplay_python import *
from syscall_dict import SOCKET_SUBCALLS
from os_dict import SHUTDOWN_INT_TO_CMD, SHUTDOWN_CMD_TO_INT
from os_dict import ADDRFAM_INT_TO_FAM
from os_dict import SOCKTYPE_INT_TO_TYPE
from os_dict import PROTOFAM_INT_TO_FAM
import tracereplay_globals
import logging


def bind_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering bind entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    if should_replay_based_on_fd(fd_from_trace):
        logging.debug('Replaying this system call')
        subcall_return_success_handler(syscall_id, syscall_object, pid)
    else:
        logging.debug('Not replaying this call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=p)


def bind_exit_handler(syscall_id, syscall_object, pid):
    pass


def listen_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering listen entry handler')
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 1)
    fd_from_trace = int(syscall_object.args[0].value)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    if should_replay_based_on_fd(fd_from_trace):
        logging.debug('Replaying this system call')
        subcall_return_success_handler(syscall_id, syscall_object, pid)
    else:
        logging.debug('Not replaying this call')


def listen_exit_handler(syscall_id, syscall_object, pid):
    pass


def getpeername_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getpeername handler')
    # Pull out the info that we can check
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    fd = params[0]
    # We don't compare params[1] because it is the address of an empty buffer
    # We don't compare params[2] because it is the address of an out parameter
    # Get values from trace for comparison
    fd_from_trace = syscall_object.args[0].value
    # Check to make sure everything is the same
    if fd != int(fd_from_trace):
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'does not match file descriptor from trace ({})'
                               .format(fd, fd_from_trace))
    # Decide if this is a file descriptor we want to deal with
    if fd_from_trace in tracereplay.REPLAY_FILE_DESCRIPTORS:
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got successful getpeername call')
            addr = params[1]
            length_addr = params[2]
            length = int(syscall_object.args[2].value.strip('[]'))
            logging.debug('Addr: %d', addr)
            logging.debug('Length addr: %d', length_addr)
            logging.debug('Length: %d', length)
            sockfields = syscall_object.args[1].value
            family = sockfields[0].value
            port = int(sockfields[1].value)
            ip = sockfields[2].value
            logging.debug('Family: %s', family)
            logging.debug('Port: %d', port)
            logging.debug('Ip: %s', ip)
            if family != 'AF_INET':
                raise NotImplementedError('getpeername only '
                                              'supports AF_INET')
            tracereplay.populate_af_inet_sockaddr(pid,
                                                  addr,
                                                  port,
                                                  ip,
                                                  length_addr,
                                                  length)
        else:
            logging.debug('Got unsuccessful getpeername call')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')


def getsockname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getsockname handler')
    # Pull out the info that we can check
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # We don't compare params[1] because it is the address of an empty buffer
    # We don't compare params[2] because it is the address of an out parameter
    # Get values from trace for comparison
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # Decide if this is a file descriptor we want to deal with
    if should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got successful getsockname call')
            addr = params[1]
            length_addr = params[2]
            length = int(syscall_object.args[2].value.strip('[]'))
            logging.debug('Addr: %d', addr)
            logging.debug('Length addr: %d', length_addr)
            logging.debug('Length: %d', length)
            sockfields = syscall_object.args[1].value
            family = sockfields[0].value
            port = int(sockfields[1].value)
            ip = sockfields[2].value
            logging.debug('Family: %s', family)
            logging.debug('Port: %d', port)
            logging.debug('Ip: %s', ip)
            if family != 'AF_INET':
                raise NotImplementedError('getsockname only supports '
                                              'AF_INET')
            tracereplay.populate_af_inet_sockaddr(pid,
                                                  addr,
                                                  port,
                                                  ip,
                                                  length_addr,
                                                  length)
        else:
            logging.debug('Got unsuccessful getsockname call')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=ecx)


def getsockname_exit_handler(syscall_id, syscall_object, pid):
    pass


def shutdown_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering shutdown entry handler')
    # Pull out the info we can check
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 2)
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # TODO: We need to check the 'how' parameter here
    # Check to make sure everything is the same
    # Decide if we want to replay this system call
    if should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=params)


def setsockopt_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering setsockopt handler')
    # Pull out what we can compare
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd_from_trace = int(syscall_object.args[0].value)
    optval_addr = params[3]
    # We don't check param[3] because it is an address of an empty buffer
    # We don't check param[4] because it is an address of an empty length
    # Check to make sure everything is the same
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # We should always replay calls to bad file descriptors because
    # there is no reason not to
    if int(syscall_object.ret[0]) == -1 \
       or should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        optval_len = int(syscall_object.args[4].value)
        if optval_len != 4:
            raise NotImplementedError('setsockopt() not implemented for '
                                          'optval sizes other than 4')
        optval = int(syscall_object.args[3].value.strip('[]'))
        logging.debug('Optval: %s', optval)
        logging.debug('Optval Length: %s', optval_len)
        logging.debug('Optval addr: %x', optval_addr % 0xffffffff)
        noop_current_syscall(pid)
        logging.debug('Writing values')
        tracereplay.populate_int(pid, optval_addr, optval)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=params)


def getsockopt_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getsockopt handler')
    # Pull out what we can compare
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 5)
    fd_from_trace = int(syscall_object.args[0].value)
    optval_addr = params[3]
    optval_len_addr = params[4]
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # This if is sufficient for now for the implemented options
    if params[1] != 1 or params[2] != 4:
        raise NotImplementedError('Unimplemented getsockopt level or optname')
    if should_replay_based_on_fd(fd_from_trace):
        logging.info('Replaying this system call')
        optval_len = int(syscall_object.args[4].value.strip('[]'))
        if optval_len != 4:
            raise NotImplementedError('getsockopt() not implemented for '
                                          'optval sizes other than 4')
        optval = int(syscall_object.args[3].value.strip('[]'))
        logging.debug('Optval: %s', optval)
        logging.debug('Optval Length: %s', optval_len)
        logging.debug('Optval addr: %x', optval_addr % 0xffffffff)
        logging.debug('Optval Lenght addr: %d', optval_len_addr % 0xffffffff)
        noop_current_syscall(pid)
        logging.debug('Writing values')
        tracereplay.populate_int(pid, optval_addr, optval)
        tracereplay.populate_int(pid, optval_len_addr, 4)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=params)


def connect_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering connect entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    validate_integer_argument(pid, syscall_object, 2, 2, params=params)
    trace_fd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(trace_fd):
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=params)


def connect_exit_handler(syscall_id, syscall_object, pid):
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    if ret_val_from_execution != ret_val_from_trace:
        raise ReplayDeltaError('Return value from execution ({}) differs '
                               'from return value from trace ({})'
                               .format(ret_val_from_execution,
                                       ret_val_from_trace))


def socket_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering socket exit handler')
    fd_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    fd_from_trace = int(syscall_object.ret[0])
    if offset_file_descriptor(fd_from_trace) != fd_from_execution:
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'differs from file descriptor from '
                               'trace ({})'
                               .format(fd_from_execution, fd_from_trace))
    if fd_from_execution >= 0:
        add_os_fd_mapping(fd_from_execution, fd_from_trace)
    tracereplay.poke_register(pid, tracereplay.EAX, fd_from_trace)


# TODO: There is a lot more checking to be done here
def socket_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering socket subcall entry handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    # Only PF_INET and PF_LOCAL socket calls are handled
    execution_is_PF_INET = (params[0] == tracereplay.PF_INET)
    trace_is_PF_INET = (str(syscall_object.args[0]) == '[\'PF_INET\']')
    execution_is_PF_LOCAL = (params[0] == 1)  # define PF_LOCAL 1
    trace_is_PF_LOCAL = (str(syscall_object.args[0]) == '[\'PF_LOCAL\']')
    logging.debug('Execution is PF_INET: %s', execution_is_PF_INET)
    logging.debug('Trace is PF_INET: %s', trace_is_PF_INET)
    logging.debug('Exeuction is PF_LOCAL: %s', execution_is_PF_LOCAL)
    logging.debug('Trace is PF_LOCAL: %s', trace_is_PF_LOCAL)
    if execution_is_PF_INET != trace_is_PF_INET:
        raise Exception('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    if execution_is_PF_LOCAL != trace_is_PF_LOCAL:
        raise Exception('Encountered socket subcall with mismatch between '
                        'execution protocol family and trace protocol family')
    # Decide if we want to deal with this socket call or not
    if trace_is_PF_INET or \
       execution_is_PF_INET or \
       trace_is_PF_LOCAL or \
       execution_is_PF_LOCAL:
        noop_current_syscall(pid)
        fd = int(syscall_object.ret[0])
        logging.debug('File Descriptor from trace: %s', fd)
        add_replay_fd(fd)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Ignoring non-PF_INET call to socket')


def accept_subcall_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Checking if line from trace is interrupted accept')
    # Hack to fast forward through interrupted accepts
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted accept. Will advance past')
        tracereplay_globals.rc.advance_trace()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'accept':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, ecx, 3)
    sockaddr_addr = params[1]
    sockaddr_len_addr = params[2]
    fd_from_trace = syscall_object.args[0].value
    validate_integer_argument(pid, syscall_object, 0, 0, params=params)
    # Decide if this is a system call we want to replay
    if should_replay_based_on_fd(fd_from_trace):
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.args[1].value != 'NULL':
            sockfields = syscall_object.args[1].value
            family = sockfields[0].value
            port = int(sockfields[1].value)
            ip = sockfields[2].value
            sockaddr_length = int(syscall_object.args[2].value.strip('[]'))
            logging.debug('Family: %s', family)
            logging.debug('Port: %s', port)
            logging.debug('IP: %s', ip)
            logging.debug('sockaddr Length: %s', sockaddr_length)
            logging.debug('sockaddr addr: %x', sockaddr_addr & 0xffffffff)
            logging.debug('sockaddr length addr: %x',
                          sockaddr_len_addr & 0xffffffff)
            logging.debug('pid: %s', pid)
            tracereplay.populate_af_inet_sockaddr(pid,
                                                  sockaddr_addr,
                                                  port,
                                                  ip,
                                                  sockaddr_len_addr,
                                                  sockaddr_length)
        if syscall_object.ret[0] != -1:
            ret = syscall_object.ret[0]
            if ret in tracereplay.REPLAY_FILE_DESCRIPTORS:
                raise Exception('Syscall object return value ({}) already '
                                'exists in tracked file descriptors list ({})'
                                .format(ret,
                                        tracereplay.REPLAY_FILE_DESCRIPTORS))
            tracereplay.REPLAY_FILE_DESCRIPTORS.append(ret)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object, params_addr=params)


def accept_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering accept exit handler')
    fd_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    fd_from_trace = int(syscall_object.ret[0])
    if offset_file_descriptor(fd_from_trace) != fd_from_execution:
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'differs from file descriptor from '
                               'trace ({})'
                               .format(fd_from_execution, fd_from_trace))
    if fd_from_execution >= 0:
        add_os_fd_mapping(fd_from_execution, fd_from_trace)
    tracereplay.poke_register(pid, tracereplay.EAX, fd_from_trace)


def socketcall_debug_printer(pid, orig_eax, syscall_object):
    subcall_debug_printers = {
        1: socket_debug_printer,
        9: send_debug_printer,
        13: shutdown_debug_printer
    }
    subcall_id = tracereplay.peek_register(pid, tracereplay.EBX)
    logging.debug('Got subcall {} {}'.format(subcall_id,
                                             SOCKET_SUBCALLS[subcall_id]))
    try:
        subcall_debug_printers[subcall_id](pid, syscall_object)
    except KeyError as e:
        logging.warning('This subcall ({}) has no debug printer'
                        .format(subcall_id))
        raise e


def send_debug_printer(pid, syscall_object):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 4)
    addr = params[1]
    size = params[2]
    data = tracereplay.copy_address_range(pid, addr, addr + size)
    logging.debug('This call tried to send: %s', data.encode('string-escape'))


def shutdown_debug_printer(pid, syscall_object):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 2)
    fd = params[0]
    cmd = params[1]
    logging.debug('This call tried to shutdown: %d', fd)
    logging.debug('Command: %d: %s', cmd, SHUTDOWN_INT_TO_CMD[params[1]])


def socket_debug_printer(pid, syscall_object):
    p = tracereplay.peek_register(pid, tracereplay.ECX)
    params = extract_socketcall_parameters(pid, p, 3)
    logging.debug('Domain: %s', ADDRFAM_INT_TO_FAM[params[0]])
    logging.debug('Type: %s', SOCKTYPE_INT_TO_TYPE[params[1]])
    logging.debug('Protocol: %s', PROTOFAM_INT_TO_FAM[params[2]])
