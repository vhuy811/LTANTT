import unittest
from network_traffic_analyzer import NetworkTrafficAnalyzer


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    def test_get_network_stats(self):
        nta = NetworkTrafficAnalyzer()
        stats = nta.get_network_stats()
        self.assertIsInstance(stats, dict)
