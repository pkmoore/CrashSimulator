# This checker determins whether or not the application under test checks to
# make sure the source file hasn't changed during the copy process. To pass,
# the application must have called stat64 or lstat64 on the source followed by
# a call to open on the source, and a call to fstat64 on the file descriptor
# returned by the open call.


class FileReplacedDuringCopyChecker:
    def __init__(self, filename):
        self.filename = filename
        self.source_automaton = StatOpenFstatAutomaton(self.filename)

    def transition(self, syscall_object):
        self.source_automaton.transition(syscall_object)

    def is_accepting(self):
        return self.source_automaton.is_accepting()


class XattrsCopiedDuringCopyChecker:
    def __init__(self, filename):
        self.filename = filename
        self.copy_automaton = XattrsCopiedInBulkAutomaton(self.filename)

    def transition(self, syscall_object):
        self.copy_automaton.transition(syscall_object)

    def is_accepting(self):
        return self.copy_automaton.is_accepting()


# Accepts traces where an attempt to rename() the target filename returns
# EXDEV.
# NOTE: some applications specify cross disk move by user input so this
# automaton is not useful in all situations (e.g. mmv)
class RenameEXDEVAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': 'rename has not been attempted on {} yet'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'Got rename that failed with EXDEV',
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'rename':
                if self.filename in syscall_object.args[0].value:
                    if syscall_object.ret[1] == 'EXDEV':
                        self.current_state = self.states[1]
        else:
            # There is no way to exit state 1
            pass

    def is_accepting(self):
        return self.current_state['accepting']


# Rejects traces where /dev/urandom is opened and read from as part of a copy
# process. How do we know this is what the program is doing? For example,
# a program could simply be getting some random data from /dev/urandom.
# Likely incomplete handling of some system call orderings.

class UrandomReadDuringCopyAutomaton:
    def __init__(self):
        self.states = [{'id': 0,
                     'comment': '/dev/urandom has not been opened yet',
                     'accepting': True},
                    {'id': 1,
                     'comment': '/dev/urandom is open but has not been '
                                'read from yet',
                     'accepting': True},
                    {'id': 2,
                     'comment': '/dev/urandom is has been read from',
                     'accepting': True},
                    {'id': 3,
                     'comment': 'the data has been written to destination file',
                     'accepting':False}]

        self.data_register = None
        self.urandom_fd = None


    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if 'open' in syscall_object.name:
                if '/dev/urandom' in syscall_object.args[0]:
                    self.current_state = self.states[1]
                    self.urandom_fd = int(syscall_object.ret[0])
        if self.current_state['id'] == 1:
            if


    def is_accepting(self):
        return self.current_state['accepting']


# Accepts traces where every xattr that was read from the source file is
# applied to the destination file. Will fail on some orderings
class XattrsCopiedInBulkAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.states = [{'id': 0,
                        'comment': '{} has not been opened yet'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'Reading attributes',
                        'accepting': False},
                       {'id': 2,
                        'comment': 'Writing attributes',
                        'accepting': False},
                       {'id': 3,
                        'comment': 'All attributes written',
                        'accepting': True}]
        self.current_state = self.states[0]
        self.fd_register = None
        self.attrs = []

    # Needs to take into account failed calls
    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if 'fgetxattr' in syscall_object.name:
                if self.fd_register == int(syscall_object.args[0].value) \
                   and syscall_object.args[2].value != '0x0':
                    self.attrs += [syscall_object.args[1].value]
            if 'fsetxattr' in syscall_object.name:
                if syscall_object.args[1].value in self.attrs:
                    self.attrs.remove(syscall_object.args[1].value)
                self.current_state = self.states[2]
        elif self.current_state['id'] == 2:
            if 'fsetxattr' in syscall_object.name:
                if syscall_object.args[1].value in self.attrs:
                    self.attrs.remove(syscall_object.args[1].value)
                if len(self.attrs) == 0:
                    self.current_state = self.states[3]
        elif self.current_state['id'] == 3:
            # It is not possible to leave this state
            pass

    def is_accepting(self):
        return self.current_state['accepting']


class AtLeastOnceWithArgAutomaton:
    def __init__(self, name, arg, pos):
        self.name = name
        self.arg = arg
        self.pos = pos
        self.states = [{'id': 0,
                        'comment': '{} not yet called with {} in position {}'
                                   .format(self.name, self.arg, self.pos),
                        'accepting': False},
                       {'id': 1,
                        'comment': '{} has been called with {} in position {}'
                                   .format(self.name, self.arg, self.pos),
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if self.name in syscall_object.name \
                    and self.arg in syscall_object.arg[self.pos].value:
                self.current_state = self.states[1]


class StatOpenFstatAutomaton:
    def __init__(self, filename):
        self.filename = filename
        self.fd_register = None
        self.states = [{'id': 0,
                        'comment': 'stat64/lstat64 not yet called on {}'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 1,
                        'comment': 'open not yet called on {}'
                                   .format(self.filename),
                        'accepting': False},
                       {'id': 2,
                        'comment': 'fstat64 not yet called on {}'
                            .format(self.filename),
                        'accepting': False},
                       {'id': 3,
                        'comment': 'expected calls have been made',
                        'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0:
            if syscall_object.name == 'stat64' \
                    or syscall_object.name == 'lstat64':
                if self.filename in syscall_object.args[0].value:
                    self.current_state = self.states[1]
        elif self.current_state['id'] == 1:
            if syscall_object.name == 'open':
                if self.filename in syscall_object.args[0].value:
                    self.fd_register = int(syscall_object.ret[0])
                    self.current_state = self.states[2]
        elif self.current_state['id'] == 2:
            if syscall_object.name == 'fstat64':
                if self.fd_register == int(syscall_object.args[0].value):
                    self.current_state = self.states[3]
        elif self.current_state['id'] == 3:
            # It is not possible to transition out of this state
            pass
        else:
            raise RuntimeError('StatOpenFstatAutomaton for {} tried to '
                               'transition with an illegal current state'
                               .format(self.filename))

    def is_accepting(self):
        return self.current_state['accepting']



