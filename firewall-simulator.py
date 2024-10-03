def simple_firewall(request_ip, blocked_ips):
    if request_ip in blocked_ips:
        return "Access blocked"
    else:
        return "Access granted"

# Example usage
blocked_ips = ['192.168.1.1', '10.0.0.1']
request_ip = '192.168.1.1'
result = simple_firewall(request_ip, blocked_ips)
print(result)
