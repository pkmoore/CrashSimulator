import tracereplay
import os
import logging
import binascii
from struct import pack, unpack
from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS
from errno_dict import ERRNO_CODES
from os_dict import OS_CONST, STAT_CONST

tracereplay.entering_syscall = True
tracereplay.handled_syscalls = 0
tracereplay.system_calls = None
tracereplay.REPLAY_FILE_DESCRIPTORS = [tracereplay.STDIN]
tracereplay.OS_FILE_DESCRIPTORS = [{'os_fd': 0, 'trace_fd': 0},
                                   {'os_fd': 1, 'trace_fd': 1}]


# This function leaves the child process in a state of waiting at the point
# just before execution returns to user code.
def noop_current_syscall(pid):
    logging.debug('Nooping the current system call in pid: %s', pid)
    tracereplay.poke_register(pid, tracereplay.ORIG_EAX, 20)
    tracereplay.syscall(pid)
    next_syscall()
    skipping = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
    if skipping != 20:
        raise Exception('Nooping did not result in getpid exit. Got {}'
                        .format(skipping))
    tracereplay.entering_syscall = False


def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True


def offset_file_descriptor(fd):
    # The -1 is to account for stdin
    return fd - (len(tracereplay.REPLAY_FILE_DESCRIPTORS) - 1)


def peek_bytes(pid, address, num_bytes):
    reads = num_bytes // 4
    remainder = num_bytes % 4
    data = ''
    for i in range(reads):
        data = data + pack('<i', tracereplay.peek_address(pid, address))
        address = address + 4
    if remainder != 0:
        last_chunk = pack('<i', tracereplay.peek_address(pid, address))
        data = data + last_chunk[:remainder]
    return data


def peek_string(pid, address):
    data = ''
    while True:
        data = data + pack('<i', tracereplay.peek_address(pid, address))
        address = address + 4
        if '\0' in data:
            data = data[:data.rfind('\0')]
            return data


def extract_socketcall_parameters(pid, address, num):
    params = []
    for i in range(num):
        params += [tracereplay.peek_address(pid, address)]
        address = address + 4
    logging.debug('Extracted socketcall parameters: %s', params)
    return params


def fix_character_literals(string):
    logging.debug('Cleaning up string')
    string = string.replace('\\n', '\n')
    string = string.replace('\\r', '\r')
    string = string.replace('\"', '"')
    logging.debug('Cleaned up string:')
    logging.debug(string)
    return string


def validate_syscall(syscall_id, syscall_object):
    if syscall_id == 192 and 'mmap' in syscall_object.name:
        return
    if syscall_id == 140 and 'llseek' in syscall_object.name:
        return
    if syscall_id == 268 and 'stat' in syscall_object.name:
        return
    if syscall_object.name not in SYSCALLS[syscall_id][4:]:
        raise ReplayDeltaError('System call validation failed: from '
                               'execution: {0}({1}) is not from '
                               'trace:{2}'
                               .format(SYSCALLS[syscall_id][4:],
                                       syscall_id,
                                       syscall_object.name))


def validate_subcall(subcall_id, syscall_object):
    if syscall_object.name not in SOCKET_SUBCALLS[subcall_id][4:]:
        raise ReplayDeltaError('Subcall validation failed: from '
                               'execution: {0}({1}) is not from '
                               'trace:{2}'
                               .format(SOCKET_SUBCALLS[subcall_id][4:],
                                       subcall_id,
                                       syscall_object.name))


# Just for the record, this function is a monstrosity.
def write_buffer(pid, address, value, buffer_length):
    writes = [value[i:i+4] for i in range(0, len(value), 4)]
    trailing = len(value) % 4
    if trailing != 0:
        left = writes.pop()
    for i in writes:
        i = i[::-1]
        data = int(binascii.hexlify(i), 16)
        tracereplay.poke_address(pid, address, data)
        address = address + 4
    if trailing != 0:
        address = address
        data = tracereplay.peek_address(pid, address)
        d = pack('i', data)
        d = left + d[len(left):]
        tracereplay.poke_address(pid, address, unpack('i', d)[0])


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
                raise ValueError('Couldn\'t get integer form of return value!')
    logging.debug('Cleaned up value %s', ret_val)
    return ret_val


# Applies the return conditions from the specified syscall object to the
# syscall currently being executed by the process identified by PID. Return
# conditions at this point are: setting the return value appropriately. Setting
# the value of errno by suppling -ERROR in the eax register. This function
# should only be called in exit handlers.
def apply_return_conditions(pid, syscall_object):
    logging.debug('Applying return conditions')
    ret_val = syscall_object.ret[0]
    if syscall_object.ret[0] == -1 and syscall_object.ret[1] is not None:
        logging.debug('Got non-None errno value: %s', syscall_object.ret[1])
        error_code = ERRNO_CODES[syscall_object.ret[1]]
        logging.debug('Looked up error number: %s', error_code)
        ret_val = -error_code
        logging.debug('Will return: %s instead of %s',
                      ret_val,
                      syscall_object.ret[0])
    else:
        ret_val = cleanup_return_value(ret_val)
    logging.debug('Injecting return value %s', ret_val)
    tracereplay.poke_register(pid, tracereplay.EAX, ret_val)


# Generic handler for all calls that just need to return what they returned in
# the trace.
# Currently used by send, listen
# TODO: check this guy for required parameter checking
def subcall_return_success_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering subcall return success handler')
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Extracting parameters from address %s', ecx)
    params = extract_socketcall_parameters(pid, ecx, 1)
    fd = params[0]
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd != int(fd_from_trace):
        raise ReplayDeltaError('File descriptor from execution ({}) '
                               'differs from file descriptor from trace'
                               .format(fd, fd_from_trace))
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


class ReplayDeltaError(Exception):
    pass


def validate_integer_argument(pid, syscall_object, arg_pos, params=None):
    logging.debug('Validating integer argument (position: %d)', arg_pos)
    # EAX is the system call number
    POS_TO_REG = {0: tracereplay.EBX,
                  1: tracereplay.ECX,
                  2: tracereplay.EDX,
                  3: tracereplay.ESI,
                  4: tracereplay.EDI}
    if not params:
        arg = tracereplay.peek_register(pid, POS_TO_REG[arg_pos])
    else:
        arg = params[arg_pos]
    arg_from_trace = int(syscall_object.args[arg_pos].value)
    logging.debug('Argument from execution: %d', arg)
    logging.debug('Argument from trace: %d', arg_from_trace)
    # Check to make sure everything is the same
    # Decide if this is a system call we want to replay
    if arg_from_trace != arg:
        raise ReplayDeltaError('Argument value at position {} from '
                               'execution ({})differs argument value '
                               'from trace ({})'
                               .format(arg_pos, arg, arg_from_trace))


def add_os_fd_mapping(os_fd, trace_fd):
    logging.debug('Mappings: {}'.format(tracereplay.OS_FILE_DESCRIPTORS))
    new = {'os_fd': os_fd, 'trace_fd': trace_fd}
    logging.debug('Adding mapping: {}'.format(new))
    if len(tracereplay.OS_FILE_DESCRIPTORS) != 0:
        for i in tracereplay.OS_FILE_DESCRIPTORS:
            if i['os_fd'] == os_fd and i['trace_fd'] == trace_fd:
                raise ReplayDeltaError('Mapping ({}) already exists!')
    tracereplay.OS_FILE_DESCRIPTORS.append(new)


def remove_os_fd_mapping(os_fd, trace_fd):
    logging.debug('Mappings: {}'.format(tracereplay.OS_FILE_DESCRIPTORS))
    remove = {'os_fd': os_fd, 'trace_fd': trace_fd}
    logging.debug('Removing mapping: {}'.format(remove))
    found = False
    index = None
    for i, item in enumerate(tracereplay.OS_FILE_DESCRIPTORS):
        if item['os_fd'] == os_fd and item['trace_fd'] == trace_fd:
            found = True
            index = i
    if not found:
        raise ReplayDeltaError('Tried to remove non-existant mapping')
    tracereplay.OS_FILE_DESCRIPTORS.pop(index)


def fd_pair_for_trace_fd(trace_fd):
    logging.debug('Looking up trace file descriptor %d', trace_fd)
    res = [x for x in tracereplay.OS_FILE_DESCRIPTORS
           if x['trace_fd'] == trace_fd]
    logging.debug(res)
    if len(res) > 1:
        raise RuntimeError('More than one entry for a given trace file '
                           'descriptor')
    elif len(res) == 0:
        logging.debug('Could not find entry for trace file descriptor in list')
        return None
    else:
        return res[0]


def should_replay_based_on_fd(pid, trace_fd):
    logging.debug('Should we replay?')
    d = fd_pair_for_trace_fd(trace_fd)
    if d:
        logging.debug('Call using non-replayed fd, not replaying')
        logging.debug('Looked up trace_fd: %d', d['trace_fd'])
        logging.debug('Looked up os_fd: %d', d['os_fd'])
        execution_fd = tracereplay.peek_register(pid, tracereplay.EBX)
        logging.debug('Execution fd: %d', execution_fd)
        if d['os_fd'] != execution_fd:
            raise ReplayDeltaError('Execution file descriptor ({}) does not '
                                   'match os fd we looked up from '
                                   'OS_FILE_DESCRIPTORS list ({})'
                                   .format(execution_fd,
                                           d['os_fd']))
        logging.debug('We should not replay, there is an os fd for this call')
        return False
    logging.debug('We should replay, there is not an os fd for this call')
    return True
