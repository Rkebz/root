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
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\" onmouseover=alert(1) x=\"",
    "<img src=x onerror=alert(1)>",
    "'\"><svg/onload=alert(1)>"
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

# Function to load websites from a file
def load_websites(file_name):
    if not os.path.exists(file_name):
        print(colored(f"File {file_name} not found!", "red"))
        return []
    with open(file_name, "r") as file:
        return [line.strip() for line in file if line.strip()]

# Function to check XSS vulnerabilities
def check_xss(url):
    vulnerabilities = []
    for payload in xss_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if payload in response.text:
                vulnerabilities.append({"url": url, "payload": payload})
        except requests.exceptions.RequestException as e:
            print(colored(f"[XSS] Error testing {url}: {e}", "red"))
    return vulnerabilities

# Function to check SQL Injection vulnerabilities
def check_sql(url):
    vulnerabilities = []
    for payload in sql_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=10)
            if "syntax" in response.text.lower() or "error" in response.text.lower():
                vulnerabilities.append({"url": url, "payload": payload})
        except requests.exceptions.RequestException as e:
            print(colored(f"[SQL] Error testing {url}: {e}", "red"))
    return vulnerabilities

# Enhanced function to discover links within a website (Advanced feature)
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

# Start scanning
def scan_websites(file_name):
    websites = load_websites(file_name)
    if not websites:
        return

    results = {}

    for website in websites:
        print(colored(f"\n[+] Scanning: {website}", "cyan"))

        # Discover additional links on the website
        links = discover_links(website)
        all_urls = [website] + links
        results[website] = {"xss": [], "sql": []}

        for url in all_urls:
            # Check for XSS vulnerabilities
            xss_vulns = check_xss(url)
            if xss_vulns:
                results[website]["xss"].extend(xss_vulns)

            # Check for SQL Injection vulnerabilities
            sql_vulns = check_sql(url)
            if sql_vulns:
                results[website]["sql"].extend(sql_vulns)

    # Display results
    for website, vulnerabilities in results.items():
        print(colored(f"\n[Results for {website}]:", "green"))

        # Display XSS vulnerabilities
        if vulnerabilities["xss"]:
            print(colored("XSS Vulnerabilities Found:", "yellow"))
            for vuln in vulnerabilities["xss"]:
                print(colored(f"Payload: {vuln['payload']} | URL: {vuln['url']}", "green"))
        else:
            print(colored("No XSS vulnerabilities found.", "red"))

        # Display SQL vulnerabilities
        if vulnerabilities["sql"]:
            print(colored("SQL Injection Vulnerabilities Found:", "yellow"))
            for vuln in vulnerabilities["sql"]:
                print(colored(f"Payload: {vuln['payload']} | URL: {vuln['url']}", "green"))
        else:
            print(colored("No SQL Injection vulnerabilities found.", "red"))

    print(colored("\n[+] Scan Complete!", "light_blue"))

# Main function
if __name__ == "__main__":
    print(colored("Enter the file name containing the list of websites (e.g., list.txt):", "yellow"))
    file_name = input("> ").strip()
    scan_websites(file_name)
