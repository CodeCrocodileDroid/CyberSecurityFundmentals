from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time


class NetworkMonitor:
    def __init__(self):
        self.packet_count = defaultdict(int)
        self.traffic_stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'sources': defaultdict(int)
        }

    def packet_handler(self, packet):
        """Handle incoming packets"""
        self.traffic_stats['total_packets'] += 1

        if IP in packet:
            src_ip = packet[IP].src
            self.traffic_stats['sources'][src_ip] += 1

            # Protocol detection
            if TCP in packet:
                self.traffic_stats['protocols']['TCP'] += 1
            elif UDP in packet:
                self.traffic_stats['protocols']['UDP'] += 1
            elif ICMP in packet:
                self.traffic_stats['protocols']['ICMP'] += 1

    def start_monitoring(self, duration=30):
        """Start packet monitoring"""
        print(f"Starting network monitoring for {duration} seconds...")
        sniff(prn=self.packet_handler, timeout=duration)
        self.display_stats()

    def display_stats(self):
        """Display traffic statistics"""
        print("\n=== Network Traffic Analysis ===")
        print(f"Total Packets: {self.traffic_stats['total_packets']}")
        print("\nProtocol Distribution:")
        for proto, count in self.traffic_stats['protocols'].items():
            print(f"  {proto}: {count}")

        print("\nTop Source IPs:")
        sorted_sources = sorted(
            self.traffic_stats['sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        for ip, count in sorted_sources:
            print(f"  {ip}: {count} packets")

# Example usage (requires root/admin privileges)
monitor = NetworkMonitor()
monitor.start_monitoring(10)  # Monitor for 10 seconds