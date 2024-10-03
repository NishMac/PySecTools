from scapy.all import sniff, IP, TCP, Raw

def extract_sni(raw_data):
    """
    Attempt to extract the SNI from raw TLS ClientHello data.
    This function tries to locate the SNI by searching for the byte pattern.
    Note: This is a very rudimentary implementation.
    """
    try:
        # Locate TLS handshake and SNI
        if b'\x16\x03' in raw_data:  # TLS Handshake magic number
            # Find the SNI extension
            sni_pos = raw_data.find(b'\x00\x00')  # SNI extension type
            if sni_pos != -1:
                # Attempt to extract the SNI
                sni_length = int.from_bytes(raw_data[sni_pos+9:sni_pos+11], byteorder='big')
                sni = raw_data[sni_pos+11:sni_pos+11+sni_length]
                return sni.decode('utf-8')
    except Exception as e:
        print(f"Error extracting SNI: {e}")
    return None

def packet_callback(packet):
    """
    Callback function to process packets.
    Filters for TCP packets to port 443 and attempts to extract SNI.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        if packet.haslayer(Raw):
            sni = extract_sni(packet[Raw].load)
            if sni:
                print(f"[HTTPS] {packet[IP].src} is visiting {sni}")

# Sniff for HTTPS traffic on port 443
print("Starting to monitor HTTPS traffic on the network...")
sniff(filter="tcp port 443", prn=packet_callback, store=0)
