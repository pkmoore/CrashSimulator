import binascii
import tracereplay

# Horrible hack
buffer_address = 0
buffer_size = 0

def noop_current_syscall(pid):
    tracereplay.poke_register(pid, tracereplay.ORIG_EAX, 20)

def write_buffer(pid, address, value, buffer_length):
    writes = [value[i:i+4] for i in range(0, len(value), 4)]
    for i in writes:
        data = int(binascii.hexlify(i), 16)
        tracereplay.poke_address(pid, address, data)
        address = address + 4

def handle_syscall(syscall_id, syscall_object, entering, pid):
    if syscall_id != 3:
        return
    if entering:
        read_entry_handler(syscall_id, syscall_object, entering, pid)
    else:
        read_exit_handler(syscall_id, syscall_object, entering, pid)

def read_entry_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    buffer_address = tracereplay.peek_register(pid, tracereplay.ECX)
    buffer_size = tracereplay.peek_register(pid, tracereplay.EDX)
    noop_current_syscall(pid)
    #horrible hack to deal with the fact that nooping results in the exit handler not being called
    read_exit_handler(syscall_id, syscall_object, entering, pid)

def read_exit_handler(syscall_id, syscall_object, entering, pid):
    global buffer_address
    global buffer_size
    write_buffer(pid, buffer_address, syscall_object.args[1].value.lstrip('"').rstrip('"'), buffer_size)
