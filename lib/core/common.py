class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    ENDC = '\033[0m'

    def disable(self):
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.ENDC = ''
