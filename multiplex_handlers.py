from tracereplay_python import *
import os
import logging


# A lot of the parsing in this function needs to be moved into the
# posix-omni-parser codebase. there really needs to be an "ARRAY OF FILE
# DESCRIPTORS" parsing class.
def select_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering select entry handler')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted select. Will advance past')
        syscall_object = tracereplay.system_calls.next()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'select':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    readfds = syscall_object.args[1].value.strip('[]').split(' ')
    readfds = [None if x == 'NULL' else int(x) for x in readfds]
    logging.debug('readfds: %s', readfds)
    writefds = syscall_object.args[2].value.strip('[]').split(' ')
    writefds = [None if x == 'NULL' else int(x) for x in writefds]
    logging.debug('writefds: %s', writefds)
    exceptfds = syscall_object.args[3].value.strip('[]').split(' ')
    exceptfds = [None if x == 'NULL' else int(x) for x in exceptfds]
    logging.debug('exceptfds: %s', exceptfds)
    fd = int(syscall_object.original_line
             [syscall_object.original_line.rfind('['):
              syscall_object.original_line.rfind(']')]
             .strip('[]) '))
    logging.debug('Got active file descriptor: %s', fd)
    readfds_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('readfds addr: %s', readfds_addr)
    writefds_addr = tracereplay.peek_register(pid, tracereplay.EDX)
    logging.debug('writefds addr: %s', writefds_addr)
    exceptfds_addr = tracereplay.peek_register(pid, tracereplay.ESI)
    logging.debug('exceptfds addr: %s', exceptfds_addr)

    if fd in readfds:
        logging.debug('using readfds_addr')
        addr = readfds_addr
    elif fd in writefds:
        logging.debug('using writefds_addr')
        addr = writefds_addr
    else:
        logging.debug('using exceptfds_addr')
        addr = exceptfds_addr
    logging.debug('Using Address: %s', addr)
    noop_current_syscall(pid)
    logging.debug('Populating bitmaps')
    tracereplay.populate_select_bitmaps(pid, fd, addr)
    logging.debug('Injecting return value: {}'.format(syscall_object.ret[0]))
    tracereplay.poke_register(pid, tracereplay.EAX, syscall_object.ret[0])


def poll_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering poll entry handler')
    array_address = tracereplay.peek_register(pid, tracereplay.EBX)
    noop_current_syscall(pid)
    ol = syscall_object.original_line
    ret_struct = ol[ol.rfind('('):]
    logging.debug('Poll return structure: %s', ret_struct)
    fd = int(ret_struct[ret_struct.find('=') + 1:ret_struct.find(',')])
    logging.debug('Returned file descriptor: %s', fd)
    ret_struct = ret_struct[ret_struct.find(' '):]
    revent = ret_struct[ret_struct.find('=') + 1: ret_struct.find('}')]
    if syscall_object.ret[0] != 1:
        raise NotImplementedError('Cannot handle poll calls that return more '
                                  'than one pollfd structure')
    if revent not in ['POLLIN', 'POLLOUT']:
        raise NotImplementedError('Encountered unimplemented revent in poll')
    index = _get_pollfds_array_index_for_fd(syscall_object, fd)
    logging.debug('Returned event: %s', revent)
    logging.debug('Writing poll results structure')
    logging.debug('Address: %s', array_address)
    logging.debug('File Descriptor: %s', fd)
    logging.debug('Event: %s', revent)
    logging.debug('Child PID: %s', pid)
    logging.debug('Index: %d', index)
    array_address = array_address + (index * tracereplay.POLLFDSIZE)
    logging.debug('Offset address: %s', array_address)
    if revent == 'POLLIN':
        r = tracereplay.POLLIN
    else:
        r = tracereplay.POLLOUT
    tracereplay.write_poll_result(pid,
                                  array_address,
                                  fd,
                                  r)
    apply_return_conditions(pid, syscall_object)


def _get_pollfds_array_index_for_fd(syscall_object, fd):
    polled_fds = [int(x.value[0]) for x in syscall_object.args[0].value]
    logging.debug('Polled fds: %s', polled_fds)
    logging.debug('File descriptor: %d', fd)
    for i in range(len(polled_fds)):
        if polled_fds[i] == fd:
            return i
    raise ValueError('File descriptor from trace return value was not '
                     'found in trace polled file descriptor structures')
