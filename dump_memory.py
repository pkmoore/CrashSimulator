from __future__ import print_function
import argparse
import time
from syscall_dict import SYSCALLS
from tracereplay_python import *


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SYSCALLS!')
    parser.add_argument('-c',
                        '--command',
                        help='The command to be executed',
                        required=False)
    args = vars(parser.parse_args())
    command = args['command'].split(' ')
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execvp(command[0], command)
    else:
        f = open('/proc/' + str(pid) + '/maps', 'r')
        for line in f.readlines():
            if '[stack]' in line:
                addrs = line.split(' ')[0]
                addrs = addrs.split('-')
                start = int(addrs[0], 16)
                end = int(addrs[1], 16)
        count = 0
        entering = True
        orig_eax = -1
        #tracereplay.enable_debug_output(10)
        os.mkdir('dumps')
        os.chdir('dumps')
        while next_syscall():
            orig_eax = tracereplay.peek_register(pid, tracereplay.ORIG_EAX)
            if SYSCALLS[orig_eax] == 'sys_exit_group' or \
               SYSCALLS[orig_eax] == 'sys_execve' or \
               SYSCALLS[orig_eax] == 'sys_exit':
                tracereplay.syscall(pid)
                continue
            b = tracereplay.copy_address_range(pid, start, end)
            f = open(str(count) + '-' + SYSCALLS[orig_eax] + '-' +
                     ('entry' if entering else 'exit') + '-' +
                     str(int(time.time())) +
                     '.bin', 'wb')
            f.write(b)
            f.close()
            if entering:
                entering = False
            elif not entering:
                entering = True
                count = count + 1
            tracereplay.syscall(pid)
