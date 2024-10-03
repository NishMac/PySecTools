# Vulnerability_Scanner
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# Function to get all links from a page
def get_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).scheme in ['http', 'https']:
                links.add(full_url)
        return links
    except Exception as e:
        print(f"Error fetching links from {url}: {e}")
        return set()

# Function to test for SQL Injection vulnerability
def test_sql_injection(url):
    sql_payload = "' OR '1'='1"
    vulnerable = False
    try:
        parsed = urlparse(url)
        params = re.findall(r'[\?&](\w+)=([^&]+)', parsed.query)
        for param in params:
            param_name, param_value = param
            test_url = re.sub(f"{param_name}=([^&]+)", f"{param_name}={sql_payload}", url)
            response = requests.get(test_url)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                vulnerable = True
                break
    except Exception as e:
        print(f"Error testing SQL Injection on {url}: {e}")
    return vulnerable

# Function to test for XSS vulnerability
def test_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    vulnerable = False
    try:
        parsed = urlparse(url)
        params = re.findall(r'[\?&](\w+)=([^&]+)', parsed.query)
        for param in params:
            param_name, param_value = param
            test_url = re.sub(f"{param_name}=([^&]+)", f"{param_name}={xss_payload}", url)
            response = requests.get(test_url)
            if xss_payload in response.text:
                vulnerable = True
                break
    except Exception as e:
        print(f"Error testing XSS on {url}: {e}")
    return vulnerable

# Main scanner function
def scan(url):
    print(f"Scanning {url}...")
    vulnerabilities = {}
    
    if test_sql_injection(url):
        vulnerabilities['SQL Injection'] = True
    else:
        vulnerabilities['SQL Injection'] = False
    
    if test_xss(url):
        vulnerabilities['XSS'] = True
    else:
        vulnerabilities['XSS'] = False
    
    return vulnerabilities

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com/page?param=value): ")
    links = get_links(target_url)
    all_vulnerabilities = {}
    
    for link in links:
        vulnerabilities = scan(link)
        all_vulnerabilities[link] = vulnerabilities
    
    # Generate Report
    print("\n--- Scan Report ---")
    for link, vuln in all_vulnerabilities.items():
        print(f"\nURL: {link}")
        for key, value in vuln.items():
            status = "Vulnerable" if value else "Not Vulnerable"
            print(f"  {key}: {status}")
