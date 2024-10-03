# Simple_VPN_Detector
import requests

def check_vpn(ip):
    api_key = 'your_api_key_here'
    response = requests.get(f'https://vpnapi.io/api/{ip}?key={api_key}')
    data = response.json()
    return data

# Example usage
ip = '8.8.8.8'
vpn_status = check_vpn(ip)
print(vpn_status)
