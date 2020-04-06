try:
    import sys
    from queue import Queue
    from threading import Thread
    from lib.core.exceptions import CrowbarExceptions
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))


class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get(True, None)

            if not func:
                break

            try:
                func(*args, **kargs)
            except:
                pass

            self.tasks.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.threads = []
        self.num_threads = num_threads
        self.tasks = Queue(self.num_threads)

        for _ in range(self.num_threads):
            worker = Worker(self.tasks)
            self.threads.append(worker)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        self.tasks.join()

        for _ in range(self.num_threads):
            self.add_task(None, None, None)

        for t in self.threads:
            t.join()
