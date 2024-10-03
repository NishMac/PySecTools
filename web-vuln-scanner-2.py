# Vulnerability_Scanner
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import threading
from queue import Queue
import json

# Function to get all links from a page
def get_links(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).scheme in ['http', 'https']:
                links.add(full_url)
        return links
    except Exception:
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
            response = requests.get(test_url, timeout=5)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                vulnerable = True
                break
    except Exception:
        pass
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
            response = requests.get(test_url, timeout=5)
            if xss_payload in response.text:
                vulnerable = True
                break
    except Exception:
        pass
    return vulnerable

# Function to test for CSRF vulnerability
def test_csrf(url):
    try:
        response = requests.get(url, timeout=5)
        if 'csrf' in response.text.lower():
            return False
        return True
    except Exception:
        return False

# Function to test for Directory Traversal vulnerability
def test_directory_traversal(url):
    traversal_payload = "../../../../etc/passwd"
    try:
        parsed = urlparse(url)
        path = parsed.path
        traversal_url = url.replace(path, path + traversal_payload)
        response = requests.get(traversal_url, timeout=5)
        if "root:" in response.text:
            return True
    except Exception:
        pass
    return False

# Function to test for Open Redirect vulnerability
def test_open_redirect(url):
    redirect_payload = "https://www.google.com"
    try:
        parsed = urlparse(url)
        params = re.findall(r'[\?&](\w+)=([^&]+)', parsed.query)
        for param in params:
            param_name, param_value = param
            test_url = re.sub(f"{param_name}=([^&]+)", f"{param_name}={redirect_payload}", url)
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            if response.status_code in [301, 302] and response.headers.get('Location') == redirect_payload:
                return True
    except Exception:
        pass
    return False

# Function to scan a single URL for vulnerabilities
def scan_url(url, results):
    vulnerabilities = {}
    vulnerabilities['SQL Injection'] = test_sql_injection(url)
    vulnerabilities['XSS'] = test_xss(url)
    vulnerabilities['CSRF'] = not test_csrf(url)
    vulnerabilities['Directory Traversal'] = test_directory_traversal(url)
    vulnerabilities['Open Redirect'] = test_open_redirect(url)
    results[url] = vulnerabilities

# Worker function for threading
def worker(queue, results):
    while not queue.empty():
        url = queue.get()
        scan_url(url, results)
        queue.task_done()

def main():
    target_url = input("Enter the target URL (e.g., http://example.com/page?param=value): ")
    links = get_links(target_url)
    links.add(target_url)
    queue = Queue()
    results = {}
    
    for link in links:
        queue.put(link)
    
    num_threads = 20
    threads = []
    
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(queue, results))
        t.start()
        threads.append(t)
    
    queue.join()
    
    report = {
        "target": target_url,
        "results": results
    }
    
    with open("vulnerability_report.json", "w") as f:
        json.dump(report, f, indent=4)
    
    print("\n--- Vulnerability Scan Report ---")
    for url, vuln in results.items():
        print(f"\nURL: {url}")
        for key, value in vuln.items():
            status = "Vulnerable" if value else "Not Vulnerable"
            print(f"  {key}: {status}")

if __name__ == "__main__":
    main()
