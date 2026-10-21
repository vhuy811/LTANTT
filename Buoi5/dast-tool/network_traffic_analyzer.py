import psutil


class NetworkTrafficAnalyzer:
    def get_network_stats(self):
        return psutil.net_io_counters(pernic=True)
