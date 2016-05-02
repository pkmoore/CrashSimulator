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
tracereplay.FILE_DESCRIPTORS = [tracereplay.STDIN]

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
    tracereplay.entering_syscall = False

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

def offset_file_descriptor(fd):
    # The -1 is to account for stdin
    return fd - (len(tracereplay.FILE_DESCRIPTORS) - 1)

def _exit(pid):
    os.kill(pid, signal.SIGKILL)
    sys.exit(1)

def peek_bytes(pid, address, num_bytes):
    reads = num_bytes // 4
    remainder = num_bytes % 4
    data = ''
    for i in range(reads):
        data =  data + pack('<i', tracereplay.peek_address(pid, address))
        address = address + 4
    if remainder != 0:
        last_chunk = pack('<i', tracereplay.peek_address(pid, address))
        data = data + last_chunk[:remainder]
    return data

def peek_string(pid, address):
    data = ''
    while True:
        data =  data + pack('<i', tracereplay.peek_address(pid, address))
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
                                        'trace:{2}' \
                                        .format(SYSCALLS[syscall_id][4:],
                                                syscall_id, 
                                                syscall_object.name))

def validate_subcall(subcall_id, syscall_object):
    if syscall_object.name not in SOCKET_SUBCALLS[subcall_id][4:]:
        raise ReplayDeltaError('Subcall validation failed: from '
                                        'execution: {0}({1}) is not from '
                                        'trace:{2}' \
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
                os.kill(pid, signal.SIGKILL)
                raise ValueError('Couldn\'t get integer form of return value!')
    logging.debug('Cleaned up value %s', ret_val)
    return ret_val

# Applies the return conditions from the specified syscall object to the syscall
# currently being executed by the process identified by PID. Return conditions
# at this point are: setting the return value appropriately. Setting the value
# of errno by suppling -ERROR in the eax register. This function should only be
# called in exit handlers.
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


class ReplayDeltaError(Exception):
    pass
