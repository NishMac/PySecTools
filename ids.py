# Intrusion Detection System (IDS)
import socket
import struct
import textwrap
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import threading
import time

# Define malicious signatures (for demonstration purposes)
MALICIOUS_SIGNATURES = [
    "malicious_payload_1",
    "malicious_payload_2",
    "attack_pattern_xyz"
]

# Anomaly detection threshold
ANOMALY_THRESHOLD = 100  # Example threshold for packets per second

# Dictionary to keep track of packet counts per IP
packet_counts = {}
lock = threading.Lock()

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        with lock:
            if src_ip in packet_counts:
                packet_counts[src_ip] += 1
            else:
                packet_counts[src_ip] = 1

        # Signature-based detection
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            payload = bytes(tcp_layer.payload).decode(errors='ignore')
            for signature in MALICIOUS_SIGNATURES:
                if signature in payload:
                    alert(f"Malicious signature detected from {src_ip}: {signature}")

def alert(message):
    print(f"[ALERT] {message}")

def anomaly_detection():
    while True:
        time.sleep(1)
        with lock:
            for ip, count in packet_counts.items():
                if count > ANOMALY_THRESHOLD:
                    alert(f"Anomalous traffic detected from {ip}: {count} packets/sec")
            # Reset counts after checking
            packet_counts.clear()

def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on {interface}...")
    sniff(prn=analyze_packet, iface=interface, store=False)

def main():
    # Get network interface from user
    interface = input("Enter the network interface to monitor (e.g., eth0): ")

    # Start anomaly detection thread
    anomaly_thread = threading.Thread(target=anomaly_detection, daemon=True)
    anomaly_thread.start()

    # Start sniffing packets
    start_sniffing(interface)

if __name__ == "__main__":
    main()
