import tracereplay
system_calls = None
system_call_index = 0
entering_syscall = True
handled_syscalls = 0
REPLAY_FILE_DESCRIPTORS = [tracereplay.STDIN, 1, 2]
OS_FILE_DESCRIPTORS = []
