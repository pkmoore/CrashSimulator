import logging

from os_dict import IOCTLS_INT_TO_IOCTL
from os_dict import SIGNAL_INT_TO_SIG
from os_dict import SIGPROCMASK_INT_TO_CMD
from os_dict import STACK_SS_TO_INT

# from util import *
from util import(validate_integer_argument,
                 should_replay_based_on_fd,
                 noop_current_syscall,
                 apply_return_conditions,
                 cint,
                 swap_trace_fd_to_execution_fd,
                 cleanup_return_value,
                 ReplayDeltaError,)


def getresuid_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getresuid entry handler')
    ruid = int(syscall_object.args[0].value.strip('[]'))
    euid = int(syscall_object.args[0].value.strip('[]'))
    suid = int(syscall_object.args[0].value.strip('[]'))
    ruid_addr = cint.peek_register(pid, cint.EBX)
    euid_addr = cint.peek_register(pid, cint.ECX)
    suid_addr = cint.peek_register(pid, cint.EDX)

    logging.debug('ruid: %d', ruid)
    logging.debug('euid: %d', euid)
    logging.debug('suid: %d', suid)

    logging.debug('ruid addr: %x', ruid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', euid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', suid_addr & 0xffffffff)
    noop_current_syscall(pid)

    cint.populate_unsigned_int(pid, ruid_addr, ruid)
    cint.populate_unsigned_int(pid, euid_addr, euid)
    cint.populate_unsigned_int(pid, suid_addr, suid)
    apply_return_conditions(pid, syscall_object)


def getresgid_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getresgid entry handler')
    ruid = int(syscall_object.args[0].value.strip('[]'))
    euid = int(syscall_object.args[0].value.strip('[]'))
    suid = int(syscall_object.args[0].value.strip('[]'))
    ruid_addr = cint.peek_register(pid, cint.EBX)
    euid_addr = cint.peek_register(pid, cint.ECX)
    suid_addr = cint.peek_register(pid, cint.EDX)

    logging.debug('ruid: %d', ruid)
    logging.debug('euid: %d', euid)
    logging.debug('suid: %d', suid)

    logging.debug('ruid addr: %x', ruid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', euid_addr & 0xffffffff)
    logging.debug('ruid addr: %x', suid_addr & 0xffffffff)
    noop_current_syscall(pid)

    cint.populate_unsigned_int(pid, ruid_addr, ruid)
    cint.populate_unsigned_int(pid, euid_addr, euid)
    cint.populate_unsigned_int(pid, suid_addr, suid)
    apply_return_conditions(pid, syscall_object)


def set_tid_address_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering set_tid_address_entry_handler')
    # POSIX-omni-parser treats this argument as a hex string with no 0x
    # We have to do manual cleanup here
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    addr_from_execution = cint.peek_register(pid, cint.EBX) & 0xffffffff
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('Address from execution: %x', addr_from_execution)
    if addr_from_trace != addr_from_execution:
        raise ReplayDeltaError('Address from trace ({}) does not match '
                               'address from execution ({})'
                               .format(addr_from_trace,
                                       addr_from_execution))


def set_tid_address_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering set_tid_address_exit_handler')
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    tid_from_trace = int(syscall_object.ret[0])
    # We have to use the address from the trace here for two reasons:
    #  1. We already confirmed at the traces matches execution in this regard
    #  in the entry handler
    #  2. Registers have been trashed by this point so we don't have any choice
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('TID from trace: %d', tid_from_trace)
    # We place the TID from the trace into the appropriate memory location
    # so future references are correct
    cint.populate_unsigned_int(pid, addr_from_trace, tid_from_trace)
    apply_return_conditions(pid, syscall_object)


def futex_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering futex entry handler')
    addr_from_trace = int('0x' + syscall_object.args[0].value, 16)
    addr_from_execution = cint.peek_register(pid, cint.EBX) & 0xffffffff
    logging.debug('Address from trace: %x', addr_from_trace)
    logging.debug('Address from execution: %x', addr_from_execution)
    if addr_from_trace != addr_from_execution:
        raise ReplayDeltaError('Address from trace ({}) does not match '
                               'address from execution ({})'
                               .format(addr_from_trace,
                                       addr_from_execution))


def futex_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering futex exit handler')
    ret_val_from_trace = syscall_object.ret[0]
    ret_val_from_execution = cint.peek_register(pid, cint.EAX) & 0xffffffff
    if ret_val_from_trace != ret_val_from_execution:
        raise ReplayDeltaError('Return value from trace ({}) does not match '
                               'return value from execution ({})'
                               .format(ret_val_from_trace,
                                       ret_val_from_execution))


def fadvise64_64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering fadvise_64_64 entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    validate_integer_argument(pid, syscall_object, 1, 1)
    validate_integer_argument(pid, syscall_object, 2, 2)
    if should_replay_based_on_fd(int(syscall_object.args[0].value)):
        logging.debug('Replaying this system call')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    else:
        logging.debug('Not replaying this system call')


# This handler assumes that uname cannot fail. The only documented way it can
# fail is if the buffer it is handed is somehow invalid. This code assumes that
# well written programs don't do this.
def uname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering uname handler')
    args = {x.value.split('=')[0]: x.value.split('=')[1]
            for x in syscall_object.args}
    args = {x.strip('{}'): y.strip('"{}') for x, y in args.iteritems()}
    logging.debug(args)
    address = cint.peek_register(pid, cint.EBX)
    noop_current_syscall(pid)
    cint.populate_uname_structure(pid,
                                  address,
                                  args['sysname'],
                                  args['nodename'],
                                  args['release'],
                                  args['version'],
                                  args['machine'],
                                  args['domainname'])
    apply_return_conditions(pid, syscall_object)


def getrlimit_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering getrlimit handler')
    cmd = syscall_object.args[0].value[0]
    if cmd != 'RLIMIT_STACK':
        raise Exception('Unimplemented getrlimit command {}'.format(cmd))
    addr = cint.peek_register(pid, cint.ECX)
    rlim_cur = syscall_object.args[1].value.strip('{')
    rlim_cur = rlim_cur.split('=')[1]
    if rlim_cur.find('*') == -1:
        raise Exception('Unimplemented rlim_cur format {}'.format(rlim_cur))
    rlim_cur = int(rlim_cur.split('*')[0]) * int(rlim_cur.split('*')[1])
    rlim_max = syscall_object.args[2].value.strip('}')
    rlim_max = rlim_max.split('=')[1]
    if rlim_max != 'RLIM_INFINITY':
        raise Exception('Unlimited rlim_max format {}'.format(rlim_max))
    rlim_max = 0x7fffffffffffffff
    logging.debug('rlim_cur: %s', rlim_cur)
    logging.debug('rlim_max: %x', rlim_max)
    logging.debug('Address: %s', addr)
    noop_current_syscall(pid)
    cint.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
    apply_return_conditions(pid, syscall_object)


def ioctl_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering ioctl handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    trace_fd = int(syscall_object.args[0].value)
    if not should_replay_based_on_fd(trace_fd):
        logging.debug('Not replaying this system call')
        swap_trace_fd_to_execution_fd(pid, 0, syscall_object)
        return
    logging.debug('Replaying this system call')
    edx = cint.peek_register(pid, cint.EDX)
    logging.debug('edx: %x', edx & 0xffffffff)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        cmd = syscall_object.args[1].value
        cmd_from_exe = cint.peek_register(pid, cint.ECX)
        _validate_ioctl_cmd(cmd, cmd_from_exe)
        # HACK: this if statement is terrible
        if not ('TCGETS' in cmd or 'FIONREAD' in cmd or 'TCSETSW' in cmd or
                'FIONBIO' in cmd or 'TIOCGWINSZ' in cmd or
                'TIOCSWINSZ' in cmd or 'TCSETSF' in cmd or 'TCSETS' in cmd or
                'FIOCLEX' in cmd):
            raise NotImplementedError('Unsupported ioctl command')
        if 'TIOCGWINSZ' in cmd:
            ws_row = syscall_object.args[2].value
            ws_row = int(ws_row.split('=')[1])
            ws_col = syscall_object.args[3].value
            ws_col = int(ws_col.split('=')[1])
            ws_xpixel = syscall_object.args[4].value
            ws_xpixel = int(ws_xpixel.split('=')[1])
            ws_ypixel = syscall_object.args[5].value
            ws_ypixel = int(ws_ypixel.split('=')[1].strip('}'))
            logging.debug('ws_row: %s', ws_row)
            logging.debug('ws_col: %s', ws_col)
            logging.debug('ws_xpixel: %s', ws_xpixel)
            logging.debug('ws_ypixel: %s', ws_ypixel)
            cint.populate_winsize_structure(pid,
                                            addr,
                                            ws_row,
                                            ws_col,
                                            ws_xpixel,
                                            ws_ypixel)
        elif 'FIONREAD' in cmd:
            num_bytes = int(syscall_object.args[2].value.strip('[]'))
            logging.debug('Number of bytes: %d', num_bytes)
            cint.populate_int(pid, addr, num_bytes)

        elif 'FIONBIO' in cmd:
            out_val = int(syscall_object.args[2].value.strip('[]'))
            out_addr = cint.peek_register(pid, cint.EDX)
            cint.poke_address(pid, out_addr, out_val)
        elif 'TCGETS' in cmd:
            c_iflags = syscall_object.args[2].value
            c_iflags = int(c_iflags[c_iflags.rfind('=')+1:], 16)
            c_oflags = syscall_object.args[3].value
            c_oflags = int(c_oflags[c_oflags.rfind('=')+1:], 16)
            c_cflags = syscall_object.args[4].value
            c_cflags = int(c_cflags[c_cflags.rfind('=')+1:], 16)
            c_lflags = syscall_object.args[5].value
            c_lflags = int(c_lflags[c_lflags.rfind('=')+1:], 16)
            c_line = syscall_object.args[6].value
            c_line = int(c_line[c_line.rfind('=')+1:])
            if not ('c_cc' in syscall_object.args[-1].value):
                raise NotImplementedError('Unsupported TCGETS argument format')
            cc = syscall_object.args[-1].value
            cc = cc.split('=')[1].strip('"{}')
            cc = cc.decode('string-escape')
            logging.debug('pid: %s', pid)
            logging.debug('Addr: %s', addr)
            logging.debug('cmd: %s', cmd)
            logging.debug('c_iflags: %x', c_iflags)
            logging.debug('c_oflags: %x', c_oflags)
            logging.debug('c_cflags: %x', c_cflags)
            logging.debug('c_lflags: %x', c_lflags)
            logging.debug('c_line: %s', c_line)
            logging.debug('len(cc): %s', len(cc))
            cint.populate_tcgets_response(pid, addr, c_iflags, c_oflags,
                                          c_cflags,
                                          c_lflags,
                                          c_line,
                                          cc)
        else:
            logging.debug('Got a %s ioctl() call', cmd)
            logging.debug('WARNING: NO SIDE EFFECTS REPLICATED')
    apply_return_conditions(pid, syscall_object)


def ioctl_exit_handler(syscall_id, syscall_object, pid):
    pass


def _ioctl_int_to_flag(i):
    f = IOCTLS_INT_TO_IOCTL[i]
    # HACK!
    if f == 'TIOCINQ':
        return ('TIOCINQ', 'FIONREAD')
    else:
        return (f,)


def _validate_ioctl_cmd(cmd_t, cmd_e):
    if 'or' in cmd_t:
        cmd_t = cmd_t.split(' or ')
    else:
        cmd_t = [cmd_t]
    cmd_t = set(cmd_t)
    cmd_e = _ioctl_int_to_flag(cmd_e)
    cmd_e = set(cmd_e)
    if (not (cmd_t <= cmd_e)) and (not (cmd_e <= cmd_t)):
        raise ReplayDeltaError('Command from trace (one of {}) does not match '
                               'command from execution (one of {})'
                               .format(cmd_t, cmd_e))


def prlimit64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering prlimit64 entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    have_new_limit = False
    have_old_limit = False
    if(syscall_object.args[2].value != 'NULL'
       and syscall_object.args[3].value != 'NULL'
       and syscall_object.args[4].value == 'NULL'):
            logging.debug('We have a new limit')
            have_new_limit = True
    elif(syscall_object.args[2].value == 'NULL'
         and syscall_object.args[3].value != 'NULL'
         and syscall_object.args[4].value != 'NULL'):
        logging.debug('We have an old limit')
        have_old_limit = True
    if have_new_limit and not have_old_limit:
        if syscall_object.args[1].value != 'RLIMIT_CORE':
            raise NotImplementedError('prlimit commands with a new limit only '
                                      'support RLIMIT_CORE')
        noop_current_syscall(pid)
        apply_return_conditions(pid, syscall_object)
    elif not have_new_limit and have_old_limit:
        if syscall_object.args[1].value != 'RLIMIT_NOFILE':
            raise NotImplementedError('prlimit commands other than '
                                      'RLIMIT_NOFILE are not supported')
        rlim_cur = int(syscall_object.args[3].value.split('=')[1])
        logging.debug('rlim_cur: %d', rlim_cur)
        rlim_max = syscall_object.args[4].value.split('=')[1]
        rlim_max = rlim_max.split('*')
        rlim_max = int(rlim_max[0]) * int(rlim_max[1].strip('}'))
        logging.debug('rlim_max: %d', rlim_max)
        addr = cint.peek_register(pid, cint.ESI)
        logging.debug('addr: %x', addr & 0xFFFFFFFF)
        noop_current_syscall(pid)
        cint.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
        apply_return_conditions(pid, syscall_object)
    else:
        raise NotImplementedError('prlimit64 calls with both a new and old '
                                  'limit are not supported')


def mmap2_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering mmap2 entry handler')
    validate_integer_argument(pid, syscall_object, 4, 4)
    trace_fd = int(syscall_object.args[4].value)
    if trace_fd != -1:
        swap_trace_fd_to_execution_fd(pid, 4, syscall_object)
    else:
        logging.debug('ignoring anonymous mmap2 call')


def mmap2_exit_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering mmap2 exit handler')
    ret_from_execution = cint.peek_register(pid, cint.EAX)
    ret_from_trace = cleanup_return_value(syscall_object.ret[0])
    logging.debug('Return value from execution %x', ret_from_execution)
    logging.debug('Return value from trace %x', ret_from_trace)
    if ret_from_execution < 0:
        ret_from_execution &= 0xffffffff
    if ret_from_execution != ret_from_trace:
        logging.debug('Return value from execution (%d, %x) differs '
                      'from return value from trace (%d, %x)',
                      ret_from_execution,
                      ret_from_execution,
                      ret_from_trace,
                      ret_from_trace)


def sched_getaffinity_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering sched_getaffinity entry handler')
    # We don't validate the first argument because the PID,
    # which is different for some reason?
    validate_integer_argument(pid, syscall_object, 1, 1)
    try:
        cpu_set_val = int(syscall_object.args[2].value.strip('{}'))
    except ValueError:
        raise NotImplementedError('handler cannot deal with multi-value '
                                  'cpu_sets: {}'
                                  .format(syscall_object.args[2]))
    cpu_set_addr = cint.peek_register(pid, cint.EDX)
    logging.debug('cpu_set value: %d', cpu_set_val)
    logging.debug('cpu_set address: %d', cpu_set_addr)
    noop_current_syscall(pid)
    cint.populate_cpu_set(pid, cpu_set_addr, cpu_set_val)
    apply_return_conditions(pid, syscall_object)


def sigaltstack_entry_handler(syscall_id, syscall_object, pid):
    # This madness is to deal with the fact that the omni-parser
    # messes up argument positions when dealing with structures
    if (syscall_object.args[0].value == 'NULL'
       and syscall_object.args[1].value == 'NULL'):
        have_ss = False
        have_oss = False
    elif (syscall_object.args[0].value == 'NULL'
          and syscall_object.args[1].value != 'NULL'):
            have_ss = False
            have_oss = True
            # Here, oss values are located at 1, 2, 3
            ss_sp = syscall_object.args[1].value
            ss_flags = syscall_object.args[2].value
            ss_size = syscall_object.args[3].value
    elif (syscall_object.args[0].value != 'NULL'
          and syscall_object.args[3].value == 'NULL'):
            have_ss = True
            have_oss = False
    elif (syscall_object.args[0].value != 'NULL'
          and syscall_object.args[3].value != 'NULL'):
            have_ss = True
            have_oss = True
            # here oss values are at 3, 4, 5
            ss_sp = syscall_object.args[3].value
            ss_flags = syscall_object.args[4].value
            ss_size = syscall_object.args[5].value
    else:
        raise ReplayDeltaError('Invalid parse of syscall_object')

    ss_from_execution = cint.peek_register(pid, cint.EBX)
    oss_from_execution = cint.peek_register(pid, cint.ECX)

    # Check for delta
    if ((have_oss and (oss_from_execution == 0))
       or not have_oss and (oss_from_execution != 0)):
        print(oss_from_execution)
        print(have_oss)
        raise ReplayDeltaError('Got non-NULL trace oss and null execution '
                               'oss')
    if ((have_ss and (ss_from_execution == 0))
       or not have_ss and (ss_from_execution != 0)):
        raise ReplayDeltaError('Got non-NULL trace ss and null execution '
                               'ss')

    noop_current_syscall(pid)
    if have_oss:
        # We have an oss so we need to populate the output structure
        # We've gathered the arguments required above but we need to clean them
        # up before we can use them
        ss_sp = int(ss_sp.split('=')[1])
        ss_flags = ss_flags.split('=')[1]
        ss_flags = _cleanup_ss_flags(ss_flags)
        ss_size = int(ss_size.split('=')[1].strip('}'))
        logging.debug('pid: %d', pid)
        logging.debug('addr: %d', oss_from_execution)
        logging.debug('ss_sp: %d', ss_sp)
        logging.debug('ss_flags: %d', ss_flags)
        logging.debug('ss_size: %d', ss_size)
        cint.populate_stack_structure(pid,
                                      oss_from_execution,
                                      ss_sp,
                                      ss_flags,
                                      ss_size)
    apply_return_conditions(pid, syscall_object)


def _cleanup_ss_flags(ss_flags):
    if ss_flags == '0':
        return 0
    else:
        return STACK_SS_TO_INT[ss_flags]


def brk_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to use address: %x',
                  cint.peek_register(pid, cint.EBX))


def mmap2_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to mmap2: %d',
                  cint.peek_register(pid, cint.EDI))


def munmap_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried munmap address: %x length: %d',
                  cint.peek_register(pid, cint.EBX) & 0xFFFFFFFF,
                  cint.peek_register(pid, cint.ECX))


def ioctl_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call used file descriptor: %d',
                  cint.peek_register(pid, cint.EBX))
    logging.debug('This call used command: %s',
                  IOCTLS_INT_TO_IOCTL[
                      cint.peek_register(pid, cint.ECX)])


def rt_sigaction_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call use signum: %s',
                  SIGNAL_INT_TO_SIG[
                      cint.peek_register(pid, cint.EBX)])


def rt_sigprocmask_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call used command: %s',
                  SIGPROCMASK_INT_TO_CMD[
                      cint.peek_register(pid, cint.EBX)])
