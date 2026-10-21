import time
import psutil


class RuntimeMonitor:
    def __init__(self, pid):
        self.pid = pid
        self.process = psutil.Process(pid)

    def get_cpu_usage(self):
        return self.process.cpu_percent(interval=1.0)

    def get_memory_usage(self):
        return self.process.memory_info().rss

    def get_open_files(self):
        return self.process.open_files()
