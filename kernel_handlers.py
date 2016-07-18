from tracereplay_python import *
import logging


# This handler assumes that uname cannot fail. The only documented way it can
# fail is if the buffer it is handed is somehow invalid. This code assumes that
# well written programs don't do this.
def uname_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering uname handler')
    args = {x.value.split('=')[0]: x.value.split('=')[1]
            for x in syscall_object.args}
    args = {x.strip('{}'): y.strip('"{}') for x, y in args.iteritems()}
    logging.debug(args)
    address = tracereplay.peek_register(pid, tracereplay.EBX)
    noop_current_syscall(pid)
    tracereplay.populate_uname_structure(pid,
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
    addr = tracereplay.peek_register(pid, tracereplay.ECX)
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
    tracereplay.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
    apply_return_conditions(pid, syscall_object)


def ioctl_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering ioctl handler')
    trace_fd = int(syscall_object.args[0].value)
    if not should_replay_based_on_fd(pid, trace_fd):
        logging.debug('Not replaying this system call')
        return
    logging.debug('Replaying this system call')
    edx = tracereplay.peek_register(pid, tracereplay.EDX)
    logging.debug('edx: %x', edx)
    addr = edx
    noop_current_syscall(pid)
    if syscall_object.ret[0] != -1:
        cmd = syscall_object.args[1].value
        if not ('TCGETS' in cmd or 'FIONREAD' in cmd or 'TCSETSW' in cmd or
                'FIONBIO' in cmd or 'TIOCGWINSZ' in cmd or
                'TIOCSWINSZ' in cmd or 'TCSETSF' in cmd or 'TCSETS' in cmd):
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
            tracereplay.populate_winsize_structure(pid,
                                                   addr,
                                                   ws_row,
                                                   ws_col,
                                                   ws_xpixel,
                                                   ws_ypixel)
        elif 'FIONREAD' in cmd:
            num_bytes = int(syscall_object.args[2].value.strip('[]'))
            logging.debug('Number of bytes: %d', num_bytes)
            tracereplay.poke_address(pid, addr, num_bytes)
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
            tracereplay.populate_tcgets_response(pid, addr, c_iflags, c_oflags,
                                                 c_cflags,
                                                 c_lflags,
                                                 c_line,
                                                 cc)
        else:
            logging.debug('Got a %s ioctl() call', cmd)
            logging.debug('WARNING: NO SIDE EFFECTS REPLICATED')
    apply_return_conditions(pid, syscall_object)


def prlimit64_entry_handler(syscall_id, syscall_object, pid):
    logging.debug('Entering prlimit64 entry handler')
    validate_integer_argument(pid, syscall_object, 0, 0)
    have_new_limit = False
    have_old_limit = False
    if syscall_object.args[2].value != 'NULL' and syscall_object.args[3].value != 'NULL' and syscall_object.args[4].value == 'NULL':
            logging.debug('We have a new limit')
            have_new_limit = True
    elif syscall_object.args[2].value == 'NULL' and syscall_object.args[3].value != 'NULL' and syscall_object.args[4].value != 'NULL':
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
        addr = tracereplay.peek_register(pid, tracereplay.ESI)
        logging.debug('addr: %x', addr & 0xFFFFFFFF)
        noop_current_syscall(pid)
        tracereplay.populate_rlimit_structure(pid, addr, rlim_cur, rlim_max)
        apply_return_conditions(pid, syscall_object)
    else:
        raise NotImplementedError('prlimit64 calls with both a new and old '
                                  'limit are not supported')


def brk_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to use address: %x',
                  tracereplay.peek_register(pid, tracereplay.EBX))


def mmap2_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried to mmap2: %d',
                  tracereplay.peek_register(pid, tracereplay.EDI))


def munmap_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call tried munmap address: %x length: %d',
                  tracereplay.peek_register(pid, tracereplay.EBX) & 0xFFFFFFFF,
                  tracereplay.peek_register(pid, tracereplay.ECX))


def ioctl_entry_debug_printer(pid, orig_eax, syscall_object):
    logging.debug('This call used file descriptor: %d',
                  tracereplay.peek_register(pid, tracereplay.EBX))
