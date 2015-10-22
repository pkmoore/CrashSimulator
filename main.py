from __future__ import print_function
import os
import sys
import re
import tracereplay
import posix_helpers
from system_call_dict import SYSCALLS

sys.path.append('./python_modules/posix-omni-parser/')
import Trace

#Constants
SYS_exit = 252

def next_syscall():
    s = os.wait()
    if os.WIFEXITED(s[1]):
        return False
    return True

if __name__ == '__main__':
    command = sys.argv[1]
    trace = sys.argv[2]
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execlp(command, command, command)
    else:
        in_syscall = False
        replaying = True
        t = Trace.Trace(trace)
        system_calls = [x for x in reversed(t.syscalls)]
        while next_syscall():
            orig_eax = tracereplay.get_EAX(pid)
            if SYSCALLS[orig_eax] == 'sys_execve' or orig_eax == SYS_exit:
                print('======')
                print('Got exec or exit: ' + system_calls.pop().name)
                print('======')
                tracereplay.syscall(pid)
                continue
            if not in_syscall:
                print('======')
                syscall = system_calls.pop()
                print('EAX: ' + str(orig_eax))
                print('Looked Up Syscall Name: ' + SYSCALLS[orig_eax])
                print('Syscall name from trace: ' + syscall.name)
                in_syscall = True
                print('======')
            else:
                in_syscall = False
            tracereplay.syscall(pid)
