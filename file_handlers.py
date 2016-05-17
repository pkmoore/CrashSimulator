from tracereplay_python import *
import os
import logging
from time import strptime, mktime, time


def close_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering close entry handler')
    # Pull out everything we can check
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    check_fd_from_trace = offset_file_descriptor(fd_from_trace)
    logging.debug('File descriptor from execution: %d', fd)
    logging.debug('File descriptor from trace: %d', fd_from_trace)
    # Check to make sure everything is the same
    # Decide if this is a system call we want to replay
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        if fd_from_trace != fd:
            raise ReplayDeltaError('File descriptor from execution ({}) '
                                   'differs from file descriptor from '
                                   'trace ({})'
                                   .format(fd, fd_from_trace))
        logging.info('Replaying this system call')
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got unsuccessful close call')
            fd = syscall_object.args[0].value
            try:
                tracereplay.FILE_DESCRIPTORS.remove(fd)
            except ValueError:
                pass
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        if offset_file_descriptor(fd_from_trace) != fd:
            raise ReplayDeltaError('File descriptor from execution ({}) '
                                   'differs from file descriptor from '
                                   'trace ({})'
                                   .format(fd, fd_from_trace))
        logging.info('Replaying this system call')


def close_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entring close exit handler')
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    logging.debug('Return value from trace: %d', ret_val_from_trace)
    logging.debug('Return value from execution: %d', ret_val_from_execution)
    check_ret_val_from_trace = ret_val_from_trace
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful close exit')
        errno_ret = (ERRNO_CODES[syscall_object.ret[1]] * -1)
        logging.debug('Errno return value: %d', errno_ret)
        check_ret_val_from_trace = errno_ret
    if ret_val_from_execution != check_ret_val_from_trace:
        raise Exception('Return value from execution ({}) differs from '
                        'Return value from trace ({})'
                        .format(ret_val_from_execution,
                                check_ret_val_from_trace))


def read_entry_handler(syscall_id, syscall_object, pid):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        if fd != int(fd_from_trace):
            raise Exception('File descriptor from execution differs from file '
                            'descriptor from trace')
        buffer_address = tracereplay.peek_register(pid, tracereplay.ECX)
        buffer_size = tracereplay.peek_register(pid, tracereplay.EDX)
        noop_current_syscall(pid)
        data = syscall_object.args[1].value.lstrip('"').rstrip('"')
        data = fix_character_literals(data)
        write_buffer(pid, buffer_address, data, buffer_size)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug("Ignoring read call to untracked file descriptor")


# This thing must be here to handle exits for read calls that we let pass. This
# will go away once the new "open" machinery is in place and we intercept all
# calls to read.
def read_exit_handler(syscall_id, syscall_object, pid):
    pass


# Note: This handler only takes action on syscalls made to file descriptors we
# are tracking. Otherwise it simply does any required debug-printing and lets
# it execute
def write_entry_handler(syscall_id, syscall_object, pid):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    msg_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    msg_len = tracereplay.peek_register(pid, tracereplay.EDX)
    logging.debug('Child attempted to write to FD: %s', fd)
    logging.debug('Child\'s message stored at: %s', msg_addr)
    logging.debug('Child\'s message length: %s', msg_len)
    if fd_from_trace in tracereplay.FILE_DESCRIPTORS:
        logging.debug('We care about this file descriptor. No-oping...')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


# Once again, this only has to be here until the new "open" machinery
# is in place
def write_exit_handler(syscall_id, syscall_object, pid):
    pass


def llseek_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering llseek entry handler')
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        result = int(syscall_object.args[2].value.strip('[]'))
        result_addr = int(tracereplay.peek_register(pid, tracereplay.ESI))
        logging.debug('result: %s', result)
        logging.debug('result_addr: %s', result_addr)
        logging.debug('Got successful llseek call')
        logging.debug('Populating result')
        tracereplay.populate_llseek_result(pid, result_addr, result)
    else:
        logging.debug('Got unsucceesful llseek call')
    apply_return_conditions(pid, syscall_object)


def getcwd_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getcwd entry handler')
    array_addr = tracereplay.peek_register(pid, tracereplay.EBX)
    data = str(syscall_object.args[0].value.strip('"'))
    data_length = int(syscall_object.ret[0])
    noop_current_syscall(pid)
    if data_length != 0:
        logging.debug('Got successful getcwd call')
        logging.debug('Data: %s', data)
        logging.debug('Data length: %s', data_length)
        logging.debug('Populating character array')
        tracereplay.populate_char_buffer(pid,
                                         array_addr,
                                         data,
                                         data_length)
    else:
        logging.debug('Got unsuccessful getcwd call')
    apply_return_conditions(pid, syscall_object)


def readlink_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering readlink entry handler')
    array_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    data = str(syscall_object.args[0].value.strip('"'))
    data_length = int(syscall_object.ret[0])
    noop_current_syscall(pid)
    if data_length != -1:
        logging.debug('Got successful readlink call')
        logging.debug('Data: %s', data)
        logging.debug('Data length: %s', data_length)
        logging.debug('Populating character array')
        tracereplay.populate_char_buffer(pid,
                                         array_addr,
                                         data,
                                         data_length)
    else:
        logging.debug('Got unsuccessful readlink call')
    apply_return_conditions(pid, syscall_object)


def statfs64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering statfs64 handler')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    ecx = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    logging.debug("EBX: %s, ECX: %s, EDX: %s, ESI: %s, EDI: %s",
                  ebx, ecx, edx, edi, esi)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful statfs64 call')
        f_type = syscall_object.args[2].value
        f_type = int(f_type[f_type.rfind('=')+1:].strip('{}'), 16)
        f_bsize = syscall_object.args[3].value
        f_bsize = int(f_bsize[f_bsize.rfind('=')+1:])
        f_blocks = syscall_object.args[4].value
        f_blocks = int(f_blocks[f_blocks.rfind('=')+1:])
        f_bfree = syscall_object.args[5].value
        f_bfree = int(f_bfree[f_bfree.rfind('=')+1:])
        f_bavail = syscall_object.args[6].value
        f_bavail = int(f_bavail[f_bavail.rfind('=')+1:])
        f_files = syscall_object.args[7].value
        f_files = int(f_files[f_files.rfind('=')+1:])
        f_ffree = syscall_object.args[8].value
        f_ffree = int(f_ffree[f_ffree.rfind('=')+1:])
        f_fsid1 = syscall_object.args[9].value
        f_fsid1 = int(f_fsid1[f_fsid1.rfind('=')+1:].strip('{}'))
        f_fsid2 = int(syscall_object.args[10].value.strip('{}'))
        f_namelen = syscall_object.args[11].value
        f_namelen = int(f_namelen[f_namelen.rfind('=')+1:])
        f_frsize = syscall_object.args[12].value
        f_frsize = int(f_frsize[f_frsize.rfind('=')+1:])
        f_flags = syscall_object.args[13].value
        f_flags = int(f_flags[f_flags.rfind('=')+1:].strip('{}'))
        logging.debug('pid: %d', pid)
        logging.debug('addr: %x', addr & 0xffffffff)
        logging.debug('f_type: %x', f_type)
        logging.debug('f_bsize: %s', f_bsize)
        logging.debug('f_blocks: %s', f_blocks)
        logging.debug('f_bfree: %s', f_bfree)
        logging.debug('f_bavail: %s', f_bavail)
        logging.debug('f_files: %s', f_files)
        logging.debug('f_ffree: %s', f_ffree)
        logging.debug('f_fsid1: %s', f_fsid1)
        logging.debug('f_fsid2: %s', f_fsid2)
        logging.debug('f_namelen: %s', f_namelen)
        logging.debug('f_frsize: %s', f_frsize)
        logging.debug('f_flags: %s', f_flags)
        tracereplay.populate_statfs64_structure(pid,
                                                addr,
                                                f_type,
                                                f_bsize,
                                                f_blocks,
                                                f_bfree,
                                                f_bavail,
                                                f_files,
                                                f_ffree,
                                                f_fsid1,
                                                f_fsid2,
                                                f_namelen,
                                                f_frsize,
                                                f_flags)
    apply_return_conditions(pid, syscall_object)


def lstat64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering lstat64 handler')
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        logging.debug('Got successful lstat64 call')
        raise NotImplementedError('Successful lstat64 not supported')
    apply_return_conditions(pid, syscall_object)


def open_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering open entry handler')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    fn_from_execution = peek_string(pid, ebx).strip('\0')
    fn_from_trace = syscall_object.args[0].value .strip('"').strip()
    logging.debug('Filename from trace: %s', fn_from_trace)
    logging.debug('Filename from execution: %s', fn_from_execution)
    if fn_from_execution != fn_from_trace:
        raise Exception('File name from execution ({}) differs from'
                        'file name from trace ({})'.format(fn_from_execution,
                                                           fn_from_trace))


def open_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entring open exit handler')
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    if ret_val_from_trace == -1:
        errno_ret = (ERRNO_CODES[syscall_object.ret[1]] * -1)
        logging.debug('Errno return value: %d', errno_ret)
        check_ret_val_from_trace = errno_ret
    else:
        # The -1 is to account for STDIN
        check_ret_val_from_trace = offset_file_descriptor(ret_val_from_trace)
    logging.debug('Return value from exeuction: %d', ret_val_from_execution)
    logging.debug('Return value from trace: %d', ret_val_from_trace)
    logging.debug('Check return value from trace: %d',
                  check_ret_val_from_trace)
    if ret_val_from_execution != check_ret_val_from_trace:
        raise Exception('Return value from execution ({}) differs from '
                        'check return value from trace ({})' 
                        .format(ret_val_from_execution,
                                check_ret_val_from_trace))


def fstat64_entry_handler(syscall_id, syscall_object, pid):
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    logging.debug('EBX: %x', ebx)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    logging.debug('EDX: %x', edx)
    logging.debug('ESI: %x', esi)
    logging.debug('EDI: %x', edi)
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful fstat64 call')
    else:
        logging.debug('Got successful fstat64 call')
        st_dev1 = syscall_object.args[1].value
        st_dev1 = st_dev1[st_dev1.rfind('(')+1:]
        st_dev2 = syscall_object.args[2].value
        st_dev2 = st_dev2.strip(')')
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)
        #HACK: horrible hack to deal with rdev. Fix this later
        st_rdev1 = 0
        st_rdev2 = 0
        if 'st_rdev' in syscall_object.args[10].value:
            logging.debug('Line contains an rdev')
            st_rdev1 = syscall_object.args[10].value
            st_rdev1 = int(st_rdev1.split('=')[1].strip('makedev('))
            st_rdev2 = syscall_object.args[11].value
            st_rdev2 = int(st_rdev2.strip(')'))
            mid_args = list(syscall_object.args[3:10])
            mid_args = [x.value for x in mid_args]
            time_args = list(syscall_object.args[12:])
            time_args = [x.value for x in time_args]
            #sometimes size is 0 so we need to hardcode it
            mid_args_dict = {'st_size': 0}
            mid_args_dict.update({x.split('=')[0]: x.split('=')[1]
                                  for x in mid_args})
            mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
            mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
            time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
            time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                 '%Y/%m/%d-%H:%M:%S'))) \
                             for x, y in time_args_dict.iteritems()}
            logging.debug('st_rdev1: %s', st_rdev1)
            logging.debug('st_rdev2: %s', st_rdev2)
        else:
            mid_args = list(syscall_object.args[3:11])
            mid_args = [x.value for x in mid_args]
            time_args = list(syscall_object.args[11:])
            time_args = [x.value for x in time_args]
            mid_args_dict = {x.split('=')[0]: x.split('=')[1] for x in mid_args}
            mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
            mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
            time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
            time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                     '%Y/%m/%d-%H:%M:%S'))) \
                             for x, y in time_args_dict.iteritems()}
        logging.debug('Middle Args: %s', mid_args_dict)
        logging.debug('Time Args: %s', time_args_dict)
        noop_current_syscall(pid)
        logging.debug('Injecting values into structure')
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           mid_args_dict['st_blocks'],
                                           mid_args_dict['st_nlink'],
                                           mid_args_dict['st_gid'],
                                           mid_args_dict['st_blksize'],
                                           st_rdev1,
                                           st_rdev2,
                                           mid_args_dict['st_size'],
                                           mid_args_dict['st_mode'],
                                           mid_args_dict['st_uid'],
                                           mid_args_dict['st_ino'],
                                           time_args_dict['st_ctime'],
                                           time_args_dict['st_mtime'],
                                           time_args_dict['st_atime'])
    apply_return_conditions(pid, syscall_object)


def stat64_exit_handler(syscall_id, syscall_object, pid):
    pass


def stat64_entry_handler(syscall_id, syscall_object, pid):
    # horrible work arouund
    print(syscall_object.args[0].value)
    if syscall_object.args[0].value == '"/etc/resolv.conf"':
        logging.error('Workaround for stat64 problem')
        return
    if 'st_rdev' in syscall_object.original_line:
        raise NotImplementedError('stat64 handler can\'t deal with st_rdevs!!')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    esi = tracereplay.peek_register(pid, tracereplay.ESI)
    edi = tracereplay.peek_register(pid, tracereplay.EDI)
    logging.debug('EBX: %x', ebx)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    logging.debug('EDX: %x', edx)
    logging.debug('ESI: %x', esi)
    logging.debug('EDI: %x', edi)
    noop_current_syscall(pid)
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful stat64 call')
    else:
        logging.debug('Got successful stat64 call')
        st_dev1 = syscall_object.args[1].value
        st_dev1 = st_dev1[st_dev1.rfind('(')+1:]
        st_dev2 = syscall_object.args[2].value
        st_dev2 = st_dev2.strip(')')
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)
        mid_args = list(syscall_object.args[3:11])
        mid_args = [x.value for x in mid_args]
        time_args = list(syscall_object.args[11:])
        time_args = [x.value for x in time_args]
        mid_args_dict = {x.split('=')[0]: x.split('=')[1] for x in mid_args}
        mid_args_dict['st_mode'] = cleanup_st_mode(mid_args_dict['st_mode'])
        mid_args_dict = {x: int(y) for x, y in mid_args_dict.iteritems()}
        time_args_dict = {x.split('=')[0]: x.split('=')[1] for x in time_args}
        time_args_dict = {x: int(mktime(strptime(y.strip('}'),
                                                 '%Y/%m/%d-%H:%M:%S'))) \
                         for x, y in time_args_dict.iteritems()}
        logging.debug('Middle Args: %s', mid_args_dict)
        logging.debug('Time Args: %s', time_args_dict)
        logging.debug('Injecting values into structure')
        if('resolv.conf' in syscall_object.args[0].value):
            logging.debug('Faking st_mtime for stat on resolv.conf')
            time_args_dict['st_mtime'] = int(time())
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           mid_args_dict['st_blocks'],
                                           mid_args_dict['st_nlink'],
                                           mid_args_dict['st_gid'],
                                           mid_args_dict['st_blksize'],
                                           0,
                                           0,
                                           mid_args_dict['st_size'],
                                           mid_args_dict['st_mode'],
                                           mid_args_dict['st_uid'],
                                           mid_args_dict['st_ino'],
                                           time_args_dict['st_ctime'],
                                           time_args_dict['st_mtime'],
                                           time_args_dict['st_atime'])
    apply_return_conditions(pid, syscall_object)


def cleanup_st_mode(m):
    m = m.split('|')
    tmp = 0
    for i in m:
        if i[0] == '0':
            tmp = tmp | int(i, 8)
        else:
            tmp = tmp | STAT_CONST[i]
    return tmp


def fcntl64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fcntl64 entry handler')
    operation = syscall_object.args[1].value[0].strip('[]\'')
    noop_current_syscall(pid)
    if operation == 'F_GETFL' or operation == 'F_SETFL':
        apply_return_conditions(pid, syscall_object)
    else:
        raise NotImplementedError('Unimplemented fcntl64 operation {}'
                                  .format(operation))
