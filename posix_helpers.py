def get_argument(line, index):
    args = line.split('(')
    args = args[1]
    args = args.strip('{}[])')
    args = args.split(',')
    args = [x.lstrip().rstrip() for x in args]
    return args[index]

def get_identifier(line):
    identifier = line.split('(')
    identifier = identifier[0]
    identifier = identifier.split(' ')
    identifier = identifier[-1]
    return identifier
