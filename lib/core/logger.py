try:
    import logging
    import os.path
    from lib.core.exceptions import CrowbarExceptions
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))


class Logger:
    def __init__(self, log_file, output_file, opt=None):
        self.logger_log = logging.getLogger('log_file')
        self.logger_log.setLevel(logging.INFO)

        handler_log = logging.FileHandler(os.path.join(".", log_file), "a", encoding=None, delay="true")
        handler_log.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
        handler_log.setFormatter(formatter)
        self.logger_log.addHandler(handler_log)

        if opt is not None:
            consolelogHandler = logging.StreamHandler()
            consolelogHandler.setFormatter(formatter)
            self.logger_log.addHandler(consolelogHandler)

        self.logger_output = logging.getLogger('output_file')
        self.logger_output.setLevel(logging.INFO)

        handler_out = logging.FileHandler(os.path.join(".", output_file), "a", encoding=None, delay="true")
        handler_out.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
        handler_out.setFormatter(formatter)
        self.logger_output.addHandler(handler_out)

        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(formatter)
        self.logger_output.addHandler(consoleHandler)

    def log_file(self, message):
        self.logger_log.critical(message)

    def output_file(self, message):
        self.logger_output.critical(message)
