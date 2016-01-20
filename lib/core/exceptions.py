class CrowbarExceptions(Exception):
    def __init__(self, err_mess):
        self.err = err_mess

    def __str__(self):
        return self.err
