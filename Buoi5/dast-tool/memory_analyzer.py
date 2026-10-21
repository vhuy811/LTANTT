import gc


class MemoryAnalyzer:
    def check_memory_leaks(self):
        gc.collect()
        leaks = [obj for obj in gc.garbage if hasattr(obj, '__del__')]
        return leaks

    def check_overflow(self, value):
        try:
            if isinstance(value, int) and abs(value) > 2**63:
                return True
        except:
            return False
        return False
