#!/usr/bin/env python3

import socket
import sys
import threading

# ==============================
# MODELS
# ==============================

class Port:
    """Represents a network port and its service & risk status."""
    def __init__(self, port_number, service, risk):
        self.port_number = port_number
        self.service = service
        self.risk = risk


class Host:
    """Represents a network host and its open ports."""
    def __init__(self, ip):
        self.ip = ip
        self.open_ports = []

    def add_port(self, port):
        self.open_ports.append(port)


# ==============================
# DATA STRUCTURES (LinkedList)
# ==============================

class Node:
    """Node for LinkedList to store Host objects."""
    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    """Custom LinkedList to store scan results."""
    def __init__(self):
        self.head = None

    def insert(self, data):
        new_node = Node(data)
        if not self.head:
            self.head = new_node
            return
        current = self.head
        while current.next:
            current = current.next
        current.next = new_node

    def display(self):
        if not self.head:
            print("\nNo scan results available.")
            return
        current = self.head
        while current:
            host = current.data
            print(f"\nHost: {host.ip}")
            if not host.open_ports:
                print("  No open ports found.")
#!/usr/bin/env python3

import socket
import sys
import threading

# ==============================
# MODELS
# ==============================

class Port:
    """Represents a network port and its service & risk status."""
    def __init__(self, port_number, service, risk):
        self.port_number = port_number
        self.service = service
        self.risk = risk


class Host:
    """Represents a network host and its open ports."""
    def __init__(self, ip):
        self.ip = ip
        self.open_ports = []

    def add_port(self, port):
        self.open_ports.append(port)


# ==============================
# DATA STRUCTURES (LinkedList)
# ==============================

class Node:
    """Node for LinkedList to store Host objects."""
    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    """Custom LinkedList to store scan results."""
    def __init__(self):
        self.head = None

    def insert(self, data):
        new_node = Node(data)
        if not self.head:
            self.head = new_node
            return
        current = self.head
        while current.next:
            current = current.next
        current.next = new_node

    def display(self):
        if not self.head:
            print("\nNo scan results available.")
            return
        current = self.head
        while current:
            host = current.data
            print(f"\nHost: {host.ip}")
            if not host.open_ports:
                print("  No open ports found.")
            else:
                for port in host.open_ports:
                    print(f"  Port {port.port_number} | {port.service} | {port.risk}")
            current = current.next


# ==============================
# VULNERABILITY CHECK
# ==============================

RISKY_PORTS = {
    21: "FTP (Unencrypted)",
    23: "Telnet (Unencrypted)",
    135: "RPC Service",
    445: "SMB (Common Exploit Target)"
}

def check_vulnerability(port):
    """Check if a port is potentially vulnerable."""
    return "⚠ Potentially Vulnerable" if port in RISKY_PORTS else "✓ Low Risk"


# ==============================
# SERVICE IDENTIFICATION
# ==============================

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}

def identify_service(port):
    """Return common service name for a port."""
    return COMMON_SERVICES.get(port, "Unknown")


# ==============================
# SCANNER
# ==============================

def scan_port(target_ip, port, host):
    """Scan a single TCP port and add it to host if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            service = identify_service(port)
            risk = check_vulnerability(port)
            port_obj = Port(port, service, risk)
            host.add_port(port_obj)
        sock.close()
    except:
        pass  # ignore errors for unavailable ports


def scan_host(target_ip, start_port=1, end_port=1024, use_threads=True):
    """Scan host for open TCP ports."""
    print(f"\nScanning {target_ip}...\n")
    host = Host(target_ip)
    threads = []

    for port in range(start_port, end_port + 1):
        if use_threads:
            t = threading.Thread(target=scan_port, args=(target_ip, port, host))
            t.start()
            threads.append(t)
        else:
            scan_port(target_ip, port, host)

    if use_threads:
        for t in threads:
            t.join()

    return host


# ==============================
# CLI MENU
# ==============================

def menu():
    print("\n===== Network Enumeration & Vulnerability Scanner =====")
    print("1. Scan Single Host")
    print("2. View Scan Results")
    print("3. Exit")


def main():
    results = LinkedList()

    while True:
        menu()
        choice = input("Enter choice: ").strip()

        if choice == "1":
            target_ip = input("Enter target IP: ").strip()
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                print("Invalid IP address.")
                continue
            host_result = scan_host(target_ip)
            results.insert(host_result)
            print("\nScan completed.")

        elif choice == "2":
            results.display()

        elif choice == "3":
            print("Exiting...")
            sys.exit()

        else:
            print("Invalid choice. Try again.")


# ==============================
# PROGRAM ENTRY
# ==============================

if __name__ == "__main__":
    main()
