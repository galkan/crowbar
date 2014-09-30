
try:
	import sys
	from Queue import Queue
	from threading import Thread
except ImportError,e:
  	import sys
  	sys.stdout.write("%s\n" %e)
  	sys.exit(1)


class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()

            try:
                func(*args, **kargs)
            except Exception, e:
                 print e

            self.tasks.task_done()



class ThreadPool():
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads): Worker(self.tasks)


    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))


    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()
