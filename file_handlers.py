from tracereplay_python import *
import logging
from os_dict import FCNTL64_INT_TO_CMD
from os_dict import PERM_INT_TO_PERM
from time import strptime, mktime


def unlink_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering unlink entry handler')
    name_from_execution = peek_string(pid,
                                      tracereplay.peek_register(pid,
                                                                tracereplay.EBX))
    name_from_trace = cleanup_quotes(syscall_object.args[0].value)
    logging.debug('Name from execution: %s', name_from_execution)
    logging.debug('Name from trace: %s', name_from_trace)
    if name_from_execution != name_from_trace:
        raise ReplayDeltaError('Name from execution ({}) does not match '
                               'name from trace ({})'
                               .format(name_from_execution,
                                       name_from_trace))
    if is_file_mmapd_at_any_time(name_from_trace):
        logging.debug('File is mmap\'d at some point. Will not replay')
    else:
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def rename_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('entering rename entry handler')
    name1_from_trace = cleanup_quotes(syscall_object.args[0].value)
    name1_from_execution = peek_string(pid,
                                       tracereplay.peek_register(pid,
                                                                 tracereplay.EBX))
    name2_from_trace = cleanup_quotes(syscall_object.args[1].value)
    name2_from_execution = peek_string(pid,
                                       tracereplay.peek_register(pid,
                                                                 tracereplay.ECX))
    if name1_from_execution != name1_from_trace:
        raise ReplayDeltaError('Name1 from execution ({}) does not match '
                               'name1 from trace ({})'
                               .format(name1_from_execution,
                                       name1_from_trace))
    if name2_from_execution != name2_from_trace:
        raise ReplayDeltaError('Name2 from execution ({}) does not match '
                               'name2 from trace ({})'
                               .format(name2_from_execution,
                                       name2_from_trace))
    if is_file_mmapd_at_any_time(name1_from_trace) or \
       is_file_mmapd_at_any_time(name2_from_trace):
        logging.debug('One of the involved filenames is mmapd at some point '
                      'will not replay system call')
    else:
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)


def mkdir_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering mkdir entry handler')
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def writev_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering writev entry handler')
    # Validate file descriptor
    validate_integer_argument(pid, syscall_object, 0, 0)
    # Validate iovec count
    validate_integer_argument(pid,
                              syscall_object,
                              len(syscall_object.args)-1,
                              2)
    vectors = int(syscall_object.args[-1].value)
    args = syscall_object.args[1:-1]
    logging.debug(args)
    datas = [args[x].value for x in range(0, len(args), 2)]
    datas[0] = datas[0].lstrip('[{')
    datas = [x.lstrip('{') for x in datas]
    datas = [x.lstrip('"').rstrip('"') for x in datas]
    datas = [x.decode('string-escape').encode('hex') for x in datas]
    lengths = [args[x].value for x in range(1, len(args), 2)]
    lengths[0] = lengths[0][0]
    lengths = [int(x.rstrip('}]')) for x in lengths]
    logging.debug('Vectors: %d', vectors)
    logging.debug('Datas: %s', datas)
    logging.debug('Lengths: %s', lengths)
    addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('Addr: %d', addr)
    vector_addresses = []
    for i in range(vectors):
        vector_addresses.append(tracereplay.peek_address(pid, addr + (i * 8)))
    # We may need to copy buffers over manually at some point.
    # Working for now.
    fd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(fd):
        logging.debug('We will replay this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


def writev_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering writev_exit_handler (does nothing)')


def pipe_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering pipe entry handler')
    read_end_from_trace = int(syscall_object.args[0].value)
    write_end_from_trace = int(syscall_object.args[1].value.strip(']'))
    if is_mmapd_before_close(read_end_from_trace,
                             tracereplay_globals.system_calls) \
       or is_mmapd_before_close(write_end_from_trace,
                                tracereplay_globals.system_calls):
        raise NotImplementedError('mmap() on file descriptors allocated by '
                                  'pipe() is unsupported')
    logging.debug('Read end from trace: %d', read_end_from_trace)
    logging.debug('Write end from trace: %d', write_end_from_trace)
    array_addr = tracereplay.peek_register(pid, tracereplay.EBX)
    add_replay_fd(read_end_from_trace)
    add_replay_fd(write_end_from_trace)
    noop_current_syscall(pid)
    tracereplay.populate_pipefd_array(pid,
                                      array_addr,
                                      read_end_from_trace,
                                      write_end_from_trace)
    apply_return_conditions(pid, syscall_object)


def dup_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering dup handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    oldfd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(oldfd):
        noop_current_syscall(pid)
        returned_fd = int(syscall_object.ret[0])
        add_replay_fd(returned_fd)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


def dup_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering dup exit handler')
    exec_fd = tracereplay.peek_register(pid, tracereplay.EAX)
    trace_fd = int(syscall_object.ret[0])
    logging.debug('Execution return value: %d', exec_fd)
    logging.debug('Trace return value: %d', trace_fd)

    if exec_fd != trace_fd:
        raise Exception('Return value from execution ({}) differs from '
                        'return value from trace ({})'
                        .format(exec_fd,
                                trace_fd))
    if exec_fd >= 0:
        add_os_fd_mapping(exec_fd, trace_fd)
    tracereplay.poke_register(pid, tracereplay.EAX, trace_fd)


def close_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering close entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    fd_from_trace = int(syscall_object.args[0].value)
    # We always replay unsuccessful close calls
    if int(syscall_object.ret[0])  == -1 \
       or should_replay_based_on_fd(fd_from_trace):
        noop_current_syscall(pid)
        if syscall_object.ret[0] != -1:
            logging.debug('Got successful close call')
            remove_replay_fd(fd_from_trace)
        else:
            logging.debug('Replaying unsuccessful close call')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.info('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


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
    remove_os_fd_mapping(int(syscall_object.args[0].value))


def read_entry_handler(syscall_id, syscall_object, pid):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    fd_from_trace = syscall_object.args[0].value
    logging.debug('File descriptor from execution: %s', fd)
    logging.debug('File descriptor from trace: %s', fd_from_trace)
    if fd_from_trace in tracereplay_globals.REPLAY_FILE_DESCRIPTORS:
        # file descriptor
        validate_integer_argument(pid, syscall_object, 0, 0)
        # bytes to read
        validate_integer_argument(pid, syscall_object, 2, 2)
        buffer_address = tracereplay.peek_register(pid, tracereplay.ECX)
        buffer_size_from_execution = tracereplay.peek_register(pid,
                                                               tracereplay.EDX)
        buffer_size_from_trace = int(syscall_object.args[2].value)
        logging.debug('Address: %x', buffer_address & 0xffffffff)
        logging.debug('Buffer size from execution: %d',
                      buffer_size_from_execution)
        logging.debug('Buffer size from trace: %d', buffer_size_from_trace)
        ret_val = int(syscall_object.ret[0])
        noop_current_syscall(pid)
        data = syscall_object.args[1].value
        data = cleanup_quotes(data)
        data = data.decode('string_escape')
        if len(data) != ret_val:
            raise ReplayDeltaError('Decoded bytes length ({}) does not equal '
                                   'return value from trace ({})'
                                   .format(len(data), ret_val))
        tracereplay.populate_char_buffer(pid,
                                         buffer_address,
                                         data)
        buf = tracereplay.copy_address_range(pid,
                                             buffer_address,
                                             buffer_address + ret_val)
        if buf != data:
            raise ReplayDeltaError('Data copied by read() handler doesn\'t '
                                   'match after copy')
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug("Ignoring read call to untracked file descriptor")
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


# Note: This handler only takes action on syscalls made to file descriptors we
# are tracking. Otherwise it simply does any required debug-printing and lets
# it execute
def write_entry_handler(syscall_id, syscall_object, pid):
    validate_integer_argument(pid, syscall_object, 0, 0)
    validate_integer_argument(pid, syscall_object, 2, 2)
    bytes_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    bytes_len = tracereplay.peek_register(pid, tracereplay.EDX)
    bytes_from_trace = cleanup_quotes(syscall_object.args[1].value)
    bytes_from_execution = tracereplay.copy_address_range(pid,
                                                          bytes_addr,
                                                          bytes_addr + bytes_len)
    bytes_from_trace = bytes_from_trace.decode('string-escape')
    logging.debug(bytes_from_trace.encode('hex'))
    logging.debug(bytes_from_execution.encode('hex'))
    # if bytes_from_trace != bytes_from_execution:
    #    raise ReplayDeltaError('Bytes from trace don\'t match bytes from '
    #                           'execution!')
    fd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(fd):
        print('Write: \n {} \n to to file descriptor: {}'
              .format(bytes_from_execution.encode('string-escape'),
                      fd))
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Ignoring write to un-replayed file descriptor')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


# Once again, this only has to be here until the new "open" machinery
# is in place
def write_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering write exit handler')
    ret_val = tracereplay.peek_register(pid, tracereplay.EAX)
    ret_val_from_trace = int(syscall_object.ret[0])
    logging.debug('Return value from execution: %d', ret_val)
    logging.debug('Return value from trace: %d', ret_val_from_trace)
    if ret_val != ret_val_from_trace:
        raise ReplayDeltaError('Return value from execution ({}) differed '
                               'from return value from trace ({})'
                               .format(ret_val, ret_val_from_trace))


def llseek_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering llseek entry handler')
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        logging.debug('Call using replayed file descriptor. Replaying this '
                      'system call')
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
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


def llseek_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('llseek exit handler doesn\'t do anything')


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
                                         data)
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
                                         data)
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


def open_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering open entry handler')
    ebx = tracereplay.peek_register(pid, tracereplay.EBX)
    fn_from_execution = peek_string(pid, ebx)
    fn_from_trace = syscall_object.args[0].value.strip('"')
    logging.debug('Filename from trace: %s', fn_from_trace)
    logging.debug('Filename from execution: %s', fn_from_execution)
    if fn_from_execution != fn_from_trace:
        raise Exception('File name from execution ({}) differs from '
                        'file name from trace ({})'.format(fn_from_execution,
                                                           fn_from_trace))
    fd_from_trace = int(syscall_object.ret[0])
    if fd_from_trace == -1 or not is_file_mmapd_at_any_time(fn_from_trace):
        if fd_from_trace == -1:
            logging.debug('This is an unsuccessful open call. We will replay '
                          'it')
        else:
            logging.debug('File descriptor is not mmap\'d before it is closed '
                          'so we will replay it')
            add_replay_fd(fd_from_trace)
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Resultant file descriptor is mmap\'d before close. '
                      'Will not replay')


def open_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering open exit handler')
    ret_val_from_trace = int(syscall_object.ret[0])
    ret_val_from_execution = tracereplay.peek_register(pid, tracereplay.EAX)
    if ret_val_from_trace == -1:
        errno_ret = (ERRNO_CODES[syscall_object.ret[1]] * -1)
        logging.debug('Errno return value: %d', errno_ret)
        check_ret_val_from_trace = errno_ret
    else:
        check_ret_val_from_trace = offset_file_descriptor(ret_val_from_trace)
    logging.debug('Return value from execution: %d', ret_val_from_execution)
    logging.debug('Return value from trace: %d', ret_val_from_trace)
    logging.debug('Check return value from trace: %d',
                  check_ret_val_from_trace)
    if ret_val_from_execution >= 0:
        add_os_fd_mapping(ret_val_from_execution, ret_val_from_trace)
    tracereplay.poke_register(pid, tracereplay.EAX, ret_val_from_trace)


def fstat64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fstat64 handler')
    if not should_replay_based_on_fd(int(syscall_object.args[0].value)):
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)
        return
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful fstat64 call')
    else:
        logging.debug('Got successful fstat64 call')
        # There should always be an st_dev
        idx, arg = find_arg_matching_string(syscall_object.args[1:],
                                            'st_dev')[0]
        st_dev1 = arg
        st_dev1 = int(st_dev1.split('(')[1])
        # must increment idx by 2 in order to account for slicing out the
        # initial file descriptor
        st_dev2 = syscall_object.args[idx+2].value
        st_dev2 = int(st_dev2.strip(')'))
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)

        # st_rdev is optional
        st_rdev1 = 0
        st_rdev2 = 0
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_rdev')
        if len(r) > 0:
            idx, arg = r[0]
            logging.debug('We have a st_rdev argument')
            st_rdev1 = arg
            st_rdev1 = int(st_rdev1.split('(')[1])
            st_rdev2 = syscall_object.args[idx+2].value
            st_rdev2 = int(st_rdev2.strip(')'))
            logging.debug('st_rdev1: %d', st_rdev1)
            logging.debug('st_rdev2: %d', st_rdev2)

        # st_ino
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ino')
        idx, arg = r[0]
        st_ino = int(arg.split('=')[1])
        logging.debug('st_ino: %d', st_ino)

        # st_mode
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mode')
        idx, arg = r[0]
        st_mode = int(cleanup_st_mode(arg.split('=')[1]))
        logging.debug('st_mode: %d', st_mode)

        # st_nlink
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_nlink')
        idx, arg = r[0]
        st_nlink = int(arg.split('=')[1])
        logging.debug('st_nlink: %d', st_nlink)

        # st_uid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_uid')
        idx, arg = r[0]
        st_uid = int(arg.split('=')[1])
        logging.debug('st_uid: %d', st_uid)

        # st_gid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_gid')
        idx, arg = r[0]
        st_gid = int(arg.split('=')[1])
        logging.debug('st_gid: %d', st_gid)

        # st_blocksize
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blksize')
        idx, arg = r[0]
        st_blksize = int(arg.split('=')[1])
        logging.debug('st_blksize: %d', st_blksize)

        # st_blocks
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blocks')
        idx, arg = r[0]
        st_blocks = int(arg.split('=')[1])
        logging.debug('st_block: %d', st_blocks)

        # st_size is optional
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_size')
        if len(r) >= 1:
            idx, arg = r[0]
            st_size = int(arg.split('=')[1])
            logging.debug('st_size: %d', st_size)
        else:
            st_size = 0
            logging.debug('optional st_size not present')
        # st_atime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_atime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_atime')
            st_atime = 0
        else:
            logging.debug('Got normal st_atime')
            st_atime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_atime: %d', st_atime)

        # st_mtime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mtime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_mtime')
            st_mtime = 0
        else:
            logging.debug('Got normal st_mtime')
            st_mtime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_mtime: %d', st_mtime)

        # st_ctime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ctime')
        idx, arg = r[0]
        value = arg.split('=')[1].strip('}')
        if value == '0':
            logging.debug('Got zero st_ctime')
            st_ctime = 0
        else:
            logging.debug('Got normal st_ctime')
            st_ctime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_ctime: %d', st_ctime)

        logging.debug('Injecting values into structure')
        logging.debug('pid: %d', pid)
        logging.debug('addr: %d', buf_addr)
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           st_blocks,
                                           st_nlink,
                                           st_gid,
                                           st_blksize,
                                           int(st_rdev1),
                                           int(st_rdev2),
                                           st_size,
                                           st_mode,
                                           st_uid,
                                           st_ino,
                                           st_ctime,
                                           st_mtime,
                                           st_atime)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def stat64_entry_handler(syscall_id, syscall_object, pid):
    # horrible work arouund
    if syscall_object.args[0].value == '"/etc/resolv.conf"':
        logging.error('Workaround for stat64 problem')
        return
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful stat64 call')
    else:
        logging.debug('Got successful stat64 call')
        # There should always be an st_dev
        idx, arg = find_arg_matching_string(syscall_object.args[1:],
                                            'st_dev')[0]
        st_dev1 = arg
        st_dev1 = int(st_dev1.split('(')[1])
        # must increment idx by 2 in order to account for slicing out the
        # initial file descriptor
        st_dev2 = syscall_object.args[idx+2].value
        st_dev2 = int(st_dev2.strip(')'))
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)

        # st_rdev is optional
        st_rdev1 = 0
        st_rdev2 = 0
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_rdev')
        if len(r) > 0:
            idx, arg = r[0]
            logging.debug('We have a st_rdev argument')
            st_rdev1 = arg
            st_rdev1 = int(st_rdev1.split('(')[1])
            st_rdev2 = syscall_object.args[idx+2].value
            st_rdev2 = int(st_rdev2.strip(')'))
            logging.debug('st_rdev1: %d', st_rdev1)
            logging.debug('st_rdev2: %d', st_rdev2)

        # st_ino
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ino')
        idx, arg = r[0]
        st_ino = int(arg.split('=')[1])
        logging.debug('st_ino: %d', st_ino)

        # st_mode
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mode')
        idx, arg = r[0]
        st_mode = int(cleanup_st_mode(arg.split('=')[1]))
        logging.debug('st_mode: %d', st_mode)

        # st_nlink
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_nlink')
        idx, arg = r[0]
        st_nlink = int(arg.split('=')[1])
        logging.debug('st_nlink: %d', st_nlink)

        # st_uid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_uid')
        idx, arg = r[0]
        st_uid = int(arg.split('=')[1])
        logging.debug('st_uid: %d', st_uid)

        # st_gid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_gid')
        idx, arg = r[0]
        st_gid = int(arg.split('=')[1])
        logging.debug('st_gid: %d', st_gid)

        # st_blocksize
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blksize')
        idx, arg = r[0]
        st_blksize = int(arg.split('=')[1])
        logging.debug('st_blksize: %d', st_blksize)

        # st_blocks
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blocks')
        idx, arg = r[0]
        st_blocks = int(arg.split('=')[1])
        logging.debug('st_block: %d', st_blocks)

        # st_size is optional
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_size')
        if len(r) >= 1:
            idx, arg = r[0]
            st_size = int(arg.split('=')[1])
            logging.debug('st_size: %d', st_size)
        else:
            st_size = 0
            logging.debug('optional st_size not present')
        # st_atime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_atime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_atime')
            st_atime = 0
        else:
            logging.debug('Got normal st_atime')
            st_atime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_atime: %d', st_atime)

        # st_mtime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mtime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_mtime')
            st_mtime = 0
        else:
            logging.debug('Got normal st_mtime')
            st_mtime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_mtime: %d', st_mtime)

        # st_ctime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ctime')
        idx, arg = r[0]
        value = arg.split('=')[1].strip('}')
        if value == '0':
            logging.debug('Got zero st_ctime')
            st_ctime = 0
        else:
            logging.debug('Got normal st_ctime')
            st_ctime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_ctime: %d', st_ctime)

        logging.debug('Injecting values into structure')
        logging.debug('pid: %d', pid)
        logging.debug('addr: %d', buf_addr)
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           st_blocks,
                                           st_nlink,
                                           st_gid,
                                           st_blksize,
                                           int(st_rdev1),
                                           int(st_rdev2),
                                           st_size,
                                           st_mode,
                                           st_uid,
                                           st_ino,
                                           st_ctime,
                                           st_mtime,
                                           st_ctime)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def lstat64_entry_handler(syscall_id, syscall_object, pid):
    buf_addr = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('ECX: %x', (buf_addr & 0xffffffff))
    if syscall_object.ret[0] == -1:
        logging.debug('Got unsuccessful lstat64 call')
    else:
        logging.debug('Got successful lstat64 call')
        # There should always be an st_dev
        idx, arg = find_arg_matching_string(syscall_object.args[1:],
                                            'st_dev')[0]
        st_dev1 = arg
        st_dev1 = int(st_dev1.split('(')[1])
        # must increment idx by 2 in order to account for slicing out the
        # initial file descriptor
        st_dev2 = syscall_object.args[idx+2].value
        st_dev2 = int(st_dev2.strip(')'))
        logging.debug('st_dev1: %s', st_dev1)
        logging.debug('st_dev2: %s', st_dev2)

        # st_rdev is optional
        st_rdev1 = 0
        st_rdev2 = 0
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_rdev')
        if len(r) > 0:
            idx, arg = r[0]
            logging.debug('We have a st_rdev argument')
            st_rdev1 = arg
            st_rdev1 = int(st_rdev1.split('(')[1])
            st_rdev2 = syscall_object.args[idx+2].value
            st_rdev2 = int(st_rdev2.strip(')'))
            logging.debug('st_rdev1: %d', st_rdev1)
            logging.debug('st_rdev2: %d', st_rdev2)

        # st_ino
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ino')
        idx, arg = r[0]
        st_ino = int(arg.split('=')[1])
        logging.debug('st_ino: %d', st_ino)

        # st_mode
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mode')
        idx, arg = r[0]
        st_mode = int(cleanup_st_mode(arg.split('=')[1]))
        logging.debug('st_mode: %d', st_mode)

        # st_nlink
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_nlink')
        idx, arg = r[0]
        st_nlink = int(arg.split('=')[1])
        logging.debug('st_nlink: %d', st_nlink)

        # st_uid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_uid')
        idx, arg = r[0]
        st_uid = int(arg.split('=')[1])
        logging.debug('st_uid: %d', st_uid)

        # st_gid
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_gid')
        idx, arg = r[0]
        st_gid = int(arg.split('=')[1])
        logging.debug('st_gid: %d', st_gid)

        # st_blocksize
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blksize')
        idx, arg = r[0]
        st_blksize = int(arg.split('=')[1])
        logging.debug('st_blksize: %d', st_blksize)

        # st_blocks
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_blocks')
        idx, arg = r[0]
        st_blocks = int(arg.split('=')[1])
        logging.debug('st_block: %d', st_blocks)

        # st_size is optional
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_size')
        if len(r) >= 1:
            idx, arg = r[0]
            st_size = int(arg.split('=')[1])
            logging.debug('st_size: %d', st_size)
        else:
            st_size = 0
            logging.debug('optional st_size not present')
        # st_atime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_atime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_atime')
            st_atime = 0
        else:
            logging.debug('Got normal st_atime')
            st_atime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_atime: %d', st_atime)

        # st_mtime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_mtime')
        idx, arg = r[0]
        value = arg.split('=')[1]
        if value == '0':
            logging.debug('Got zero st_mtime')
            st_mtime = 0
        else:
            logging.debug('Got normal st_mtime')
            st_mtime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_mtime: %d', st_mtime)

        # st_ctime
        r = find_arg_matching_string(syscall_object.args[1:],
                                     'st_ctime')
        idx, arg = r[0]
        value = arg.split('=')[1].strip('}')
        if value == '0':
            logging.debug('Got zero st_ctime')
            st_ctime = 0
        else:
            logging.debug('Got normal st_ctime')
            st_ctime = int(mktime(strptime(value, '%Y/%m/%d-%H:%M:%S')))
        logging.debug('st_ctime: %d', st_ctime)

        logging.debug('Injecting values into structure')
        logging.debug('pid: %d', pid)
        logging.debug('addr: %d', buf_addr)
        tracereplay.populate_stat64_struct(pid,
                                           buf_addr,
                                           int(st_dev1),
                                           int(st_dev2),
                                           st_blocks,
                                           st_nlink,
                                           st_gid,
                                           st_blksize,
                                           int(st_rdev1),
                                           int(st_rdev2),
                                           st_size,
                                           st_mode,
                                           st_uid,
                                           st_ino,
                                           st_ctime,
                                           st_mtime,
                                           st_ctime)
    noop_current_syscall(pid)
    apply_return_conditions(pid, syscall_object)


def fchown_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fchown entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    # TODO: Validate second argument here. Issue -> it is a flags object
    validate_integer_argument(pid, syscall_object, 2, 2)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')


def fchmod_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fchmod entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')


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
    validate_integer_argument(pid, syscall_object, 0, 0)
    trace_fd = int(syscall_object.args[0].value)
    if should_replay_based_on_fd(trace_fd):
        operation = syscall_object.args[1].value[0].strip('[]\'')
        noop_current_syscall(pid)
        if operation == 'F_GETFL' or operation == 'F_SETFL':
            apply_return_conditions(pid, syscall_object)
        else:
            raise NotImplementedError('Unimplemented fcntl64 operation {}'
                                      .format(operation))
    else:
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)


def open_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to open: %s',
                  peek_string(pid,
                              tracereplay.peek_register(pid,
                                                        tracereplay.EBX)))


def write_entry_debug_printer(pid, orig_eax, syscall_object):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    addr = tracereplay.peek_register(pid, tracereplay.ECX)
    data_count = tracereplay.peek_register(pid, tracereplay.EDX)
    data = tracereplay.copy_address_range(pid, addr, addr + data_count)
    logging.debug('This call tried to write: %s', data.encode('string-escape'))
    logging.debug('Length: %d', data_count)
    logging.debug('File descriptor: %d', fd)


def fstat64_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to fstat: %s',
                  tracereplay.peek_register(pid, tracereplay.EBX))


def close_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to close: %s',
                  tracereplay.peek_register(pid, tracereplay.EBX))


def dup_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to dup: %d',
                  tracereplay.peek_register(pid, tracereplay.EBX))


def fcntl64_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to fcntl: %d',
                  tracereplay.peek_register(pid, tracereplay.EBX))
    logging.debug('fcntl command: %s',
                  FCNTL64_INT_TO_CMD[
                      tracereplay.peek_register(pid, tracereplay.ECX)])
    logging.debug('Param 3: %d',
                  tracereplay.peek_register(pid, tracereplay.EDX))


def stat64_entry_debug_printer(pid, orig_eax, syscall_object):
    path_addr = tracereplay.peek_register(pid, tracereplay.EBX)
    logging.debug('This call tried to use path: %s',
                  peek_string(pid, path_addr))


def access_entry_debug_printer(pid, orig_eax, syscall_object):
    path_addr = tracereplay.peek_register(pid, tracereplay.EBX)
    mode = tracereplay.peek_register(pid, tracereplay.ECX)
    logging.debug('This call tried to use path: %s',
                  peek_string(pid, path_addr))
    logging.debug('Mode: %s',
                  PERM_INT_TO_PERM[mode])


def read_entry_debug_printer(pid, orig_eax, syscall_object):
    fd = tracereplay.peek_register(pid, tracereplay.EBX)
    logging.debug('Tried to read from fd: %d', fd)


def cleanup_quotes(quo):
    if quo.startswith('"'):
        quo = quo[1:]
    if quo.endswith('"'):
        quo = quo[:-1]
    return quo
