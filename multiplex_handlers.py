import logging
import re

from util import *
from poll_parser import (
    parse_poll_results,
    parse_poll_input,
)


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
    seconds = 0
    microseconds = 0
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
        in_pollfds = parse_poll_input(syscall_object)
        out_pollfds = parse_poll_results(syscall_object)
        logging.debug('Input pollfds: %s', in_pollfds)
        logging.debug('Returned event: %s', out_pollfds)
        logging.debug('Pollfd array address: %s', array_address)
        logging.debug('Child PID: %s', pid)
        index = 0
        for i in in_pollfds:
            array_address = array_address + (index * cint.POLLFDSIZE)
            found = False
            for o in out_pollfds:
                if i['fd'] == o['fd']:
                    cint.write_poll_result(pid,
                                           array_address,
                                           o['fd'],
                                           o['revents'])
                    found = True

            if not found:
                # For applications that re-use the pollfd array, we must clear
                # the revents field in case they don't do it themselves.
                cint.write_poll_result(pid,
                                       array_address,
                                       i['fd'],
                                       0)
            index += 1
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
