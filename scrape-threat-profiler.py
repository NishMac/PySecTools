import requests
from bs4 import BeautifulSoup

def scrape_security_alerts(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    alerts = soup.find_all('a', class_='alert-title')
    return [alert.get_text() for alert in alerts]

# Example usage
url = 'https://www.securitysite.com/alerts'
alerts = scrape_security_alerts(url)
print(alerts)
