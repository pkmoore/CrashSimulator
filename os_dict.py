OS_CONST = {
    # asm-generic/fcntl.h
    'O_RDWR': 00000002,
    'SOL_SOCKET': 1,
    'SO_ERROR': 4,
    # asm-generic/fcntl.h
    'O_APPEND': 00002000
}

SOCK_CONST = {
    'SOCK_STREAM': 1,
    'SOCK_DGRAM': 2
}

STAT_CONST = {
    'S_IFMT': 00170000,
    'S_IFSOCK': 0140000,
    'S_IFLNK': 0120000,
    'S_IFREG': 0100000,
    'S_IFBLK': 0060000,
    'S_IFDIR': 0040000,
    'S_IFCHR': 0020000,
    'S_IFIFO': 0010000,
    'S_ISUID': 0004000,
    'S_ISGID': 0002000,
    'S_ISVTX': 0001000
}
