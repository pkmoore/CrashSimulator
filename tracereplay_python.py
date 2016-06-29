import tracereplay
import os
import logging
import binascii
import itertools
import time
from struct import pack, unpack
from syscall_dict import SYSCALLS
from syscall_dict import SOCKET_SUBCALLS
from errno_dict import ERRNO_CODES
from os_dict import OS_CONST, STAT_CONST

tracereplay.entering_syscall = True
tracereplay.handled_syscalls = 0
tracereplay.system_calls = None
tracereplay.REPLAY_FILE_DESCRIPTORS = [tracereplay.STDIN, 1, 2]
tracereplay.OS_FILE_DESCRIPTORS = []


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
    # The -3 is to account for stdin, stdout, stderr
    return fd - (len(tracereplay.REPLAY_FILE_DESCRIPTORS) - 3)


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
            while '\0' in data:
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
    if syscall_object.ret[0] == -1:
        logging.debug('Handling unsuccessful call')
    else:
        logging.debug('Handling successful call')
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
    if d and trace_fd not in tracereplay.REPLAY_FILE_DESCRIPTORS:
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
        logging.debug('We should not replay, there is an os fd for this call '
                      'and no entry for it in REPLAY_FILE_DESCRIPTORS')
        return False
    elif not d and trace_fd in tracereplay.REPLAY_FILE_DESCRIPTORS:
        logging.debug('This fd %d has no OS_FILE_DESCRIPTORS entry but does '
                      'exist in REPLAY_FILE_DESCRIPTORS. Should be replayed',
                      trace_fd)
        return True
    elif d and trace_fd in tracereplay.REPLAY_FILE_DESCRIPTORS:
        raise ReplayDeltaError('This fd ({}) is in both the OS file '
                               'descriptor list and the replay file '
                               'descriptor list'.format(trace_fd))
    else:
        raise ReplayDeltaError('No entry in either list for fd {}. Maybe this '
                               'is an improperly handled unsuccessful call?'
                               .format(trace_fd))
    logging.debug('We should replay, there is not an os fd for this call')
    return True


def find_close_for_fd(fd):
    logging.debug('Finding close for file descriptor: %d', fd)
    # This list will not have the current syscall in it
    # Must unroll the iterator
    tracereplay.system_calls, tmp_syscalls = itertools.tee(tracereplay.system_calls)
    tmp_syscalls = list(tmp_syscalls)
    close_index = None
    for index, obj in enumerate(tmp_syscalls):
        if obj.name == 'close' and int(obj.args[0].value) == fd:
            close_index = index
            logging.debug('Found close for this open\'s file descriptor %d '
                          'calls away', close_index)
            break
    if not close_index:
        logging.debug('File descriptor is never closed')
    return close_index


def is_mmapd_before_close(fd):
    # This list will not have the current syscall in it
    # Must unroll the iterator
    tracereplay.system_calls, tmp_syscalls = itertools.tee(tracereplay.system_calls)
    tmp_syscalls = list(tmp_syscalls)
    close_index = find_close_for_fd(fd)
    if close_index:
        logging.debug('Looking for mmap2 of fd %d up to %d calls away',
                      fd, close_index)
        tmp_syscalls = tmp_syscalls[:close_index]
    else:
        logging.debug('Looking for mmap2 of fd %d before end of trace', fd)
    for index, obj in enumerate(tmp_syscalls):
        if obj.name == 'mmap2' and int(obj.args[4].value) == fd:
            logging.debug('Found mmap2 call for fd %d %d calls away',
                          fd, index)
            return True
    logging.debug('This file descriptor is not mmap2\'d before it is closed')
    return False


def add_replay_fd(fd):
    if fd in tracereplay.REPLAY_FILE_DESCRIPTORS:
        raise ReplayDeltaError('File descriptor ({}) alread exists in replay '
                               'file descriptors list'.format(fd))
    tracereplay.REPLAY_FILE_DESCRIPTORS.append(fd)


def remove_replay_fd(fd):
    if fd not in tracereplay.REPLAY_FILE_DESCRIPTORS:
        raise ReplayDeltaError('Tried to remove non-existant file descriptor '
                               '({}) from replay file descriptor lists'
                               .format(fd))
    tracereplay.REPLAY_FILE_DESCRIPTORS.remove(fd)


def find_arg_matching_string(args, s):
    r = [(x, y.value) for x, y in enumerate(args) if s in y.value]
    if len(r) > 1:
        raise ReplayDeltaError('Found more than one arg for specified string '
                               '({}) ({})'.format(r, s))
    return r


def get_stack_start_and_end(pid):
        f = open('/proc/' + str(pid) + '/maps', 'r')
        for line in f.readlines():
            if '[stack]' in line:
                addrs = line.split(' ')[0]
                addrs = addrs.split('-')
                start = int(addrs[0], 16)
                end = int(addrs[1], 16)
        return (start, end)


def dump_stack(pid, syscall_id, entering):
    start, end = get_stack_start_and_end(pid)
    b = tracereplay.copy_address_range(pid, start, end)
    f = open(str(tracereplay.handled_syscalls) + '-' +
             SYSCALLS[syscall_id] + '-' +
             ('entry' if entering else 'exit') + '-' +
             str(int(time.time())) + '-' +
             'REPLAY-' +
             '.bin', 'wb')
    f.write(b)
    f.close()
