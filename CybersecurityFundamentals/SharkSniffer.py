# First install: pip install pyshark
import pyshark
import time
from collections import defaultdict


class PySharkNetworkMonitor:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)

    def packet_handler(self, packet):
        """Handle incoming packets"""
        self.packet_count += 1

        try:
            # Get protocol information
            if 'IP' in packet:
                src_ip = packet.ip.src
                self.ip_stats[src_ip] += 1

                # Protocol detection
                if 'TCP' in packet:
                    self.protocol_stats['TCP'] += 1
                elif 'UDP' in packet:
                    self.protocol_stats['UDP'] += 1
                elif 'ICMP' in packet:
                    self.protocol_stats['ICMP'] += 1

            # Print basic packet info
            if self.packet_count <= 10:  # Show first 10 packets
                print(f"Packet {self.packet_count}: {packet.highest_layer}")
                if 'IP' in packet:
                    print(f"  From: {packet.ip.src} -> {packet.ip.dst}")

        except Exception as e:
            pass  # Ignore malformed packets

    def start_monitoring(self, duration=30, interface='Wi-Fi'):
        """Start packet monitoring"""
        print(f"Starting network monitoring on {interface} for {duration} seconds...")

        try:
            # Create capture object
            capture = pyshark.LiveCapture(interface=interface)

            # Start sniffing with timeout
            start_time = time.time()
            for packet in capture.sniff_continuously():
                self.packet_handler(packet)
                if time.time() - start_time > duration:
                    break

        except Exception as e:
            print(f"Error during capture: {e}")
            print("Make sure you're running as administrator and the interface name is correct")

        self.display_stats()

    def display_stats(self):
        """Display traffic statistics"""
        print("\n=== Network Traffic Analysis ===")
        print(f"Total Packets: {self.packet_count}")
        print("\nProtocol Distribution:")
        for proto, count in self.protocol_stats.items():
            print(f"  {proto}: {count}")

        print("\nTop Source IPs:")
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f"  {ip}: {count} packets")


# Example usage
if __name__ == "__main__":
    # List available interfaces first
    try:
        capture = pyshark.LiveCapture()
        print("Available interfaces:")
        for i, interface in enumerate(capture.interfaces):
            print(f"  {i}: {interface}")
    except Exception as e:
        print(f"Error listing interfaces: {e}")

    # Start monitoring (you may need to change interface name)
    monitor = PySharkNetworkMonitor()
    # monitor.start_monitoring(duration=10, interface='Wi-Fi')  # Adjust interface name