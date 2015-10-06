import tracereplay
import os
import sys

if __name__ == '__main__':
    command = sys.argv[1]
    trace = sys.argv[2]
    print command
    print trace
    pid = os.fork()
    if pid == 0:
        tracereplay.traceme()
        os.execlp('ls', 'ls', '-al')
    else:
        in_syscall = False
        while True:
            s = os.wait()
            if os.WIFEXITED(s[1]):
                break
            else:
                orig_eax = tracereplay.get_EAX(pid)
                # We don't want to count the execve or exit because it throws our state off (it never exits)
                if orig_eax == 11 or orig_eax == 252:
                    tracereplay.syscall(pid)
                    continue
                if not in_syscall:
                   in_syscall = True
                   print 'We are in a ' + str(orig_eax)
                else:
                    in_syscall = False
                    print 'We are about to leave ' + str(orig_eax)
                tracereplay.syscall(pid)
