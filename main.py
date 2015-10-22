from __future__ import print_function
import os
import sys
import re
import tracereplay
import posix_helpers
from system_call_dict import SYSCALLS
from system_call_dict import SOCKET_SUBCALLS

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
                print('Got exec or exit: ' + system_calls.pop().name)
                tracereplay.syscall(pid)
                continue
            if not in_syscall:
                line = system_calls.pop().name
                syscall_name = SYSCALLS[orig_eax]
                identifier = posix_helpers.get_identifier(line)
                print('EAX: ' + str(orig_eax) + ' Got syscall: ' + syscall_name)
                print('Line in trace: ' + line)
                if re.search(syscall_name[4:], line) is None:
                    if identifier not in SOCKET_SUBCALLS.values():
                        print('SYSTEM CALL MISMATCH: ' + identifier + ' : ' + syscall_name)
                        sys.exit(1)
                if SYSCALLS[orig_eax] == 'sys_socketcall':
                    print('Entering SYS_socketcall')
                    ebx = tracereplay.get_EBX(pid)
                    print('Call: ' + str(orig_eax))
                    print('Subcall: ' + str(ebx))
                in_syscall = True
            else:
                in_syscall = False
            tracereplay.syscall(pid)
