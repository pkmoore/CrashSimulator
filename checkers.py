# symbolic calls:
# lstat(@f, {..., st_ino=@i, st_mode=@m, ...}) = @r -> ls[@m&S_ISLINK==1,@r==0](@f, @i)
# stat(@f, {..., st_ino=@i, ...}) = @r -> s[@r==0](@f, @i)
# rename(@sf, @tf) = _ -> rn(@sf, @tf)
# open(@f, @m, _) = _ -> c[@m&O_CREAT==1](@f)
# trigger:
# [^c[T](!s)]*; rn(!s, !t)
# anomaly response:
# [^rn(!s, !t)]*; ls[T,T](!s, ?si); [^rn(!s, !t)]*;
# ls[F,T](!t, ?ti); [^rn(!s, !t)]*; s[T](!t, !si); [^rn(!s, !t)]*



# To accomplish tracking the below with regard to arbitrary order we need a
# 'checklist' or something. State advances when a checklist item is satisfied.

# stat64("/mnt/c/test.txt", 0xbffff54c) = -1 ENOENT (No such file or directory)
# lstat64("/mnt/b/test.txt", {st_dev=makedev(8, 17), st_ino=353, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=10, st_atime=2016/10/24-00:43:10, st_mtime=2016/10/24-00:43:10, st_ctime=2016/10/24-00:43:1      0}) = 0
# lstat64("/mnt/c/test.txt", 0xbffff2c8) = -1 ENOENT (No such file or directory)
# rename("/mnt/b/test.txt", "/mnt/c/test.txt") = -1 EXDEV (Invalid cross-device link)
# unlink("/mnt/c/test.txt")         = -1 ENOENT (No such file or directory)
# open("/mnt/b/test.txt", O_RDONLY|O_LARGEFILE|O_NOFOLLOW) = 3
# fstat64(3, {st_dev=makedev(8, 17), st_ino=353, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=10, st_atime=2016/10/24-00:43:10, st_mtime=2016/10/24-00:43:10, st_ctime=2016/10/24-00:43:10}) = 0
# open("/mnt/c/test.txt", O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE, 0600) = 4
# fstat64(4, {st_dev=makedev(8, 33), st_ino=14, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=0, st_size=0, st_atime=2016/10/24-00:43:33, st_mtime=2016/10/24-00:43:33, st_ctime=2016/10/24-00:43:33}) = 0


# How to get the initial source and destination?
SOURCE = '"/mnt/b/test.txt"'
DESTINATION = '"/mnt/c/test.txt"'
SOURCE_FD = 3
DESTINATION_FD = 4


class CrossDeviceMoveChecker:
    def __init__(self):
        self.source_been_lstat64 = False
        self.destination_been_lstat64 = False
        self.destination_been_stat64 = False
        self.rename_attempted = False
        self.source_been_fstat64 = False
        self.destination_been_fstat64 = False

        self.registers = {}
        self.states = [
            {'id': 0, 'comment': 'completing steps', 'accepting': False},
            {'id': 1, 'comment': 'steps completed', 'accepting': True},
        ]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        self.complete_item(syscall_object)
        if self.current_state['id'] == 0 and self.all_items_completed():
            self.current_state = self.states[1]

    # We almost need a checklist type situation here
    # We don't have a way of knowing what the appliation is doing with the results
    # of the system call so we end up having to just accept calls whenever they happen.
    # We can't make judgements about when a call is made.

    def complete_item(self, syscall_object):
        if not self.source_been_lstat64 and is_lstat64_source(syscall_object):
            self.source_been_lstat64 = True

        if not self.destination_been_lstat64 and is_lstat64_destination(syscall_object):
            self.destination_been_lstat64 = True

        if not self.destination_been_stat64 and is_stat64_destination(syscall_object):
            self.destination_been_stat64 = True

        if not self.destination_been_fstat64 and is_fstat64_source(syscall_object):
            self.destination_been_fstat64 = True

        if not self.source_been_fstat64 and is_fstat64_destination(syscall_object):
            self.source_been_fstat64 = True

        if not self.rename_attempted and is_rename_attempt(syscall_object):
            self.rename_attempted = True

    def all_items_completed(self):
        if self.source_been_lstat64 \
         and self.destination_been_lstat64 \
         and self.destination_been_stat64 \
         and self.source_been_fstat64 \
         and self.destination_been_fstat64:
            return True
        return False

    def in_accepting_state(self):
        return self.current_state['accepting']


def is_lstat64_source(syscall_object):
    return syscall_object.name == 'lstat64' and syscall_object.args[0].value == SOURCE


def is_stat64_source(syscall_object):
    return syscall_object.name == 'stat64' and syscall_object.args[0].value == SOURCE


def is_lstat64_destination(syscall_object):
    return syscall_object.name == 'lstat64' and syscall_object.args[0].value == DESTINATION


def is_stat64_destination(syscall_object):
    return syscall_object.name == 'stat64' and syscall_object.args[0].value == DESTINATION


def is_fstat64_source(syscall_object):
    return syscall_object.name == 'fstat64' and syscall_object.args[0].value == SOURCE_FD


def is_fstat64_destination(syscall_object):
    return syscall_object.name == 'fstat64' and syscall_object.args[0].value == DESTINATION_FD


def is_rename_attempt(syscall_object):
    return syscall_object.name == 'rename' and syscall_object.args[0].value == SOURCE and syscall_object.args[1].value == DESTINATION