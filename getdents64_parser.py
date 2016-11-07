DIRENT_TYPES = {
    'DT_DIR': 8,
    'DT_REG': 4
}


def parse_getdents64_structure(syscall_object):
    if syscall_object.name != 'getdents64':
        raise ValueError('Received argument is not a getdents64 syscall object')
    if syscall_object.args[1].value == '{}':
        return []
    left_brace = syscall_object.original_line.find('{')
    right_brace = syscall_object.original_line.rfind('}')
    line = syscall_object.original_line[left_brace+2:right_brace-1]
    entries = line.split('} {')

    tmp = []
    for i in entries:
        tmp += [i.split(', ')]
    entries = tmp
    tmp = []
    tmp_dict = {}
    for i in entries:
        for j in i:
            s = j.split('=')
            k = s[0]
            v = s[1]
            tmp_dict[k] = v
        tmp += [tmp_dict]
        tmp_dict = {}
    entries = tmp

    for i in entries:
        i['d_name'] = i['d_name'].lstrip('"').rstrip('"')
        try:
            i['d_type'] = DIRENT_TYPES[i['d_type']]
        except KeyError:
            raise NotImplementedError('Unsupported d_type: {}', i['d_type'])
        i['d_ino'] = int(i['d_ino'])
        i['d_reclen'] = int(i['d_reclen'])
        i['d_off'] = int(i['d_off'])
    return entries