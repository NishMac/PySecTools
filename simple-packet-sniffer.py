# This script uses Scapy to sniff network packets and prints them. It can be extended to filter specific protocols or perform more complex analysis.
from scapy.all import sniff

def packet_callback(packet):
    print(packet.show())

# Start sniffing packets
sniff(prn=packet_callback, store=False)
