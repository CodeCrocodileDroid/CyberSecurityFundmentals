import socket
import threading
from concurrent.futures import ThreadPoolExecutor


def scan_port(host, port):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None


def port_scan(host, start_port=1, end_port=1024):
    """Scan range of ports"""
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, host, port)
                   for port in range(start_port, end_port + 1)]

        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports


def banner_grab(host, port):
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return "No banner available"


# Example usage
host = "scanme.nmap.org"  # Test host
print(f"Scanning {host}...")
open_ports = port_scan(host, 20, 100)
print(f"Open ports: {open_ports}")

if 80 in open_ports:
    print(f"Port 80 banner: {banner_grab(host, 80)}")