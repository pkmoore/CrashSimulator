from __future__ import print_function
import os
import sys
import re

import tracereplay

sys.path.append('./python_modules/posix-omni-parser/')
import StraceParser

#Constants
SYS_execve = 11
SYS_exit = 252
SYS_socketcall = 102
SYS_socketcall_socket = 1
SYS_socketcall_bind = 2

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

def is_socket_syscall(line):
    return re.search('socket\(', line) is not None or re.search('bind\(', line) is not None

def extract_return_value(line):
    return re.search(' = -?[a-zA-Z0-9]* ?', line).group(0).translate(None, '= ')

if __name__ == '__main__':
    command = sys.argv[1]
    trace = sys.argv[2]
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execlp(command, command, command)
    else:
        with open(trace, 'r') as f:
            data = f.readlines()
        data = [x.rstrip('\n') for x in data]
        socket_calls = [x for x in reversed(data) if is_socket_syscall(x)]
        in_syscall = False
        count = 0
        while next_syscall():
            orig_eax = tracereplay.get_EAX(pid)
            # We don't want to count the execve or exit because it throws our state off (it never exits)
            if orig_eax == SYS_execve or orig_eax == SYS_exit:
                tracereplay.syscall(pid)
                continue
            if not in_syscall:
               in_syscall = True
            else:
                if orig_eax == SYS_socketcall:
                    print('SYS_socketcall exiting...')
                    corresponding_line = socket_calls.pop()
                    print('Corresponding line: ' + corresponding_line)
                    ret = extract_return_value(corresponding_line)
                    tracereplay.set_EAX(pid, int(ret))
                in_syscall = False
            tracereplay.syscall(pid)
