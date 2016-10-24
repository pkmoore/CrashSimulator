class CrossDeviceMoveChecker:
    def __init__(self):
        self.registers = {}
        self.states = [{'id': 0, 'comment': 'start state', 'accepting': False},
                       {'id': 1, 'comment': 'saw rename', 'accepting': True}]
        self.current_state = self.states[0]

    def transition(self, syscall_object):
        if self.current_state['id'] == 0 and syscall_object.name == 'rename':
            self.current_state = self.states[1]

    def in_accepting_state(self):
        return self.current_state['accepting']
