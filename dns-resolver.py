# Simple DNS_Resolver
import socket

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "DNS lookup failed."

# Example usage
domain = 'google.com'
ip_address = dns_lookup(domain)
print(f"IP Address of {domain} is {ip_address}")
