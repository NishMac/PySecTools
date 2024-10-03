# A basic script to scan for open ports on a specified IP address using Python's socket library.
import socket
import threading
from queue import Queue

# Define the target
target = input("Enter target IP or hostname: ")
port_start = int(input("Enter start port (e.g., 1): "))
port_end = int(input("Enter end port (e.g., 1024): "))

# Convert hostname to IP
try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("Hostname could not be resolved.")
    exit()

# Create a queue to hold ports
port_queue = Queue()
for port in range(port_start, port_end + 1):
    port_queue.put(port)

# Lock for thread-safe printing
print_lock = threading.Lock()

# List to hold open ports
open_ports = []

# Scanner function
def port_scanner():
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with print_lock:
                    print(f"Port {port} is OPEN")
                open_ports.append(port)
            sock.close()
        except Exception as e:
            with print_lock:
                print(f"Error scanning port {port}: {e}")
        finally:
            port_queue.task_done()

# Number of threads
num_threads = 100

# Create threads
for _ in range(num_threads):
    t = threading.Thread(target=port_scanner)
    t.daemon = True
    t.start()

# Wait for the queue to be empty
port_queue.join()

# Generate Report
print("\n--- Scan Report ---")
print(f"Target: {target_ip}")
print(f"Open Ports ({len(open_ports)}): {sorted(open_ports)}")
