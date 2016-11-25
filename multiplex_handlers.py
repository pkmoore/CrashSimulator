import logging
import re

from util import *


# A lot of the parsing in this function needs to be moved into the
# posix-omni-parser codebase. there really needs to be an "ARRAY OF FILE
# DESCRIPTORS" parsing class.

# Right now, all calls to select will be replayed. We do this because this
# covers all of the real-world examples encountered thus far (i.e. we have not
# seen a select call that operated entirely on "real" file descriptors. If
# even one file descriptor is replayed we must replay the select call.

# The only issue that might pop up is a case where the file descriptor returned
# as "ready" maps to a real file descriptor that is not "ready" for a
# non-blocking call. In this case, the real call (that we allow through) would
# return EWOULDBLOCK or something like that which would result in a replay
# delta.
def select_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering select entry handler')
    while syscall_object.ret[0] == '?':
        logging.debug('Got interrupted select. Will advance past')
        syscall_object = advance_trace()
        logging.debug('Got new line %s', syscall_object.original_line)
        if syscall_object.name != 'select':
            raise Exception('Attempt to advance past interrupted accept line '
                            'failed. Next system call was not accept!')
    noop_current_syscall(pid)
    timeval_addr = None
    if syscall_object.args[4].value != 'NULL':
        timeval_addr = cint.peek_register(pid, cint.EDI)
        logging.debug('timeval_addr: %d')
        seconds = int(syscall_object.args[4].value.strip('{}'))
        microseconds = int(syscall_object.args[5].value.strip('{}'))
        logging.debug('seconds: %d', seconds)
        logging.debug('microseconds: %d', microseconds)
    readfds_addr = cint.peek_register(pid, cint.ECX)
    logging.debug('readfds addr: %x', readfds_addr & 0xFFFFFFFF)
    writefds_addr = cint.peek_register(pid, cint.EDX)
    logging.debug('writefds addr: %x', writefds_addr & 0xFFFFFFFF)
    exceptfds_addr = cint.peek_register(pid, cint.ESI)
    logging.debug('exceptfds addr: %x', exceptfds_addr & 0xFFFFFFFF)
    readfds = []
    writefds = []
    exceptfds = []
    if int(syscall_object.ret[0]) != 0:
        ol = syscall_object.original_line
        ret_line = ol.split('=')[1]
        ret_line = ret_line.split('(')[1].strip(')')
        in_substr = re.search(r'in \[(\d\s?)*\]', ret_line)
        if in_substr:
            in_substr = in_substr.group(0)
            in_fds = in_substr.split(' ')[1:]
            readfds = [int(x.strip('[]')) for x in in_fds]
        out_substr = re.search(r'out \[(\d\s?)*\]', ret_line)
        if out_substr:
            out_substr = out_substr.group(0)
            out_fds = out_substr.split(' ')[1:]
            writefds = [int(x.strip('[]')) for x in out_fds]
        if 'exc' in ret_line:
            raise NotImplementedError('outfds and exceptfds not supported')
    else:
        logging.debug('Select call timed out')
    logging.debug('Populating bitmaps')
    logging.debug('readfds: %s', readfds)
    logging.debug('writefds: %s', writefds)
    logging.debug('exceptfds: %s', exceptfds)
    cint.populate_select_bitmaps(pid,
                                        readfds_addr,
                                        readfds,
                                        writefds_addr,
                                        writefds,
                                        exceptfds_addr,
                                        exceptfds)
    logging.debug('Populating timeval structure')
    if timeval_addr:
        cint.populate_timeval_structure(pid,
                                               timeval_addr,
                                               seconds,
                                               microseconds)
    apply_return_conditions(pid, syscall_object)


# Similarly to the select() handler, all calls to poll() are replayed.
# For the same reasons...

def poll_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering poll entry handler')
    array_address = cint.peek_register(pid, cint.EBX)
    if syscall_object.ret[0] == 0:
        logging.debug('Poll call timed out')
    else:
        ol = syscall_object.original_line
        ret_struct = ol[ol.rfind('('):]
        logging.debug('Poll return structure: %s', ret_struct)
        fd = int(ret_struct[ret_struct.find('=') + 1:ret_struct.find(',')])
        logging.debug('Returned file descriptor: %s', fd)
        ret_struct = ret_struct[ret_struct.find(' '):]
        revent = ret_struct[ret_struct.find('=') + 1: ret_struct.find('}')]
        if syscall_object.ret[0] != 1:
            raise NotImplementedError('Cannot handle poll calls that return '
                                      'more than one pollfd structure')
        if revent not in ['POLLIN', 'POLLOUT']:
            raise NotImplementedError('Encountered unimplemented revent in '
                                      'poll')
        logging.debug('Returned file descriptor: %d', fd)
        logging.debug('Returned event: %s', revent)
        logging.debug('Pollfd array address: %s', array_address)
        logging.debug('Child PID: %s', pid)
        if revent == 'POLLIN':
            r = cint.POLLIN
        else:
            r = cint.POLLOUT
        found_returned_fd = False
        for index, obj in enumerate(syscall_object.args[0].value):
            array_address = array_address + (index * cint.POLLFDSIZE)
            obj_fd = syscall_object.args[0].value[index].value[0]
            if obj_fd == fd:
                cint.write_poll_result(pid,
                                              array_address,
                                              fd,
                                              r)
                found_returned_fd = True
            else:
                # For applications that re-use the pollfd array, we must clear
                # the revents field in case they don't do it themselves.
                cint.write_poll_result(pid,
                                              array_address,
                                              obj_fd,
                                              0)
        if not found_returned_fd:
            raise ReplayDeltaError('File descriptor from trace return value '
                                   'was not found in trace polled file '
                                   'descriptor structures')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def select_entry_debug_printer(pid, orig_eax, syscall_object):
    readfds_addr = cint.peek_register(pid, cint.ECX)
    writefds_addr = cint.peek_register(pid, cint.EDX)
    exceptfds_addr = cint.peek_register(pid, cint.EDI)
    logging.debug("nfds: %d", cint.peek_register(pid, cint.EBX))
    logging.debug("readfds_addr: %x", readfds_addr & 0xffffffff)
    logging.debug("writefds_addr: %x", writefds_addr & 0xffffffff)
    logging.debug("exceptfds_addr: %x", exceptfds_addr & 0xffffffff)
    if readfds_addr != 0:
        logging.debug("readfds: %s",
                      cint.get_select_fds(pid, readfds_addr))
    if writefds_addr != 0:
        logging.debug("writefds: %s",
                      cint.get_select_fds(pid, writefds_addr))
    if exceptfds_addr != 0:
        logging.debug("exceptfds_addr: %s",
                      cint.get_select_fds(pid, exceptfds_addr))
