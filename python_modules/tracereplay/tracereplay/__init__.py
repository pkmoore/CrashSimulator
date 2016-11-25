import cinterface
from checker import checker

system_calls = None
system_call_index = 0
entering_syscall = True
handled_syscalls = 0
REPLAY_FILE_DESCRIPTORS = [cinterface.STDIN, 1, 2]
OS_FILE_DESCRIPTORS = []