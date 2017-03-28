from os_dict import POLL_EVENT_TO_INT


def parse_poll_results(syscall_object):
    ol = syscall_object.original_line
    ret_struct = ol[ol.rfind('('):]
    ret_struct = ret_struct.strip('()')
    ret_struct = ret_struct.strip('[]')
    pollfds = []
    while ret_struct != '':
        closing_curl_index = ret_struct.find('}')
        tmp = ret_struct[:closing_curl_index].lstrip(' ,{').split(', ')
        tmp_dict = {}
        for i in tmp:
            entry = i.split('=')
            tmp_dict[entry[0]] = entry[1]
        pollfds += [tmp_dict]
        ret_struct = ret_struct[closing_curl_index+1:]
    for i in pollfds:
        i['fd'] = int(i['fd'])
        i['revents'] = __revents_to_int(i['revents'])
    return pollfds


def parse_poll_input(syscall_object):
    results = syscall_object.args[0].value
    pollfds = []
    for i in results:
        tmp = {}
        i = eval(str(i))
        tmp['fd'] = i[0]
        tmp['events'] = i[1]
        tmp['revents'] = i[2]
        pollfds += [tmp]
    return pollfds


def __revents_to_int(revents):
    val = 0
    if '|' in revents:
        revents = revents.split('|')
        for i in revents:
            val = val | POLL_EVENT_TO_INT[i]
    else:
        val = POLL_EVENT_TO_INT[revents]
    return val
