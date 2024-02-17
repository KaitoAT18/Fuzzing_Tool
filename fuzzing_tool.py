import argparse
from colorama import Fore
from bs4 import BeautifulSoup
import requests
import pyfiglet


# Scan hidden address

# SQL Injection
def sqli(url):
    mysql_attacks = []
    check = False

    print(Fore.GREEN + f'Target website: {url}\n' + Fore.RESET)

    # open file and read the content in a list
    with open('/Users/lehoangminh/Workspace/KTLT_FUZZING/Fuzzer_Team9/attack_vector/sqli_vector', 'r') as file:
        for line in file:
            attack = line[:-1]
            mysql_attacks.append(attack)

    for attack in mysql_attacks:
        print(Fore.GREEN + "[+]Testing... " + url + attack)
        response = requests.get(url + attack)
        if "mysql" not in response.text.lower():
            check = True
            print(Fore.RED + "[*]Attack string: " + attack + Fore.RESET)

    if check:
        print(Fore.RED + '\n[***]The website is vulnerable to SQLI' + Fore.RESET)
    else:
        print(Fore.GREEN + '\n[***]The website may be not vulnerable to SQLI' + Fore.RESET)

# XSS
def xss(url):
    # Get payload from file
    xss_payloads = []
    with open('/Users/lehoangminh/Workspace/KTLT_FUZZING/Fuzzer_Team9/attack_vector/xss_vector.txt', 'r') as file:
        for line in file:
            xss_payload = line[:-1]
            xss_payloads.append(xss_payload)

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser').find_all('input')
    data = {}
    check = False

    print(Fore.GREEN + f'Target website: {url}\n' + Fore.RESET)

    for payload in xss_payloads:
        for field in soup:
            if field['type'].lower() == 'text':
                data[field['name']] = payload

        response = requests.post(url, data=data)
        if payload in response.text:
            print(Fore.GREEN + f'[+]Payload: {payload} => returned in the response' + Fore.RESET)
            check = True

    if not check:
        print(Fore.GREEN + '\n[***]The website may be not vulnerable to XSS' + Fore.RESET)
    else:
        print(Fore.RED + '\n[***]The website is vulnerable to XSS' + Fore.RESET)

# Process mode
def process_mode(mode, url):
    if mode == 'XSS':
        xss(url)
    elif mode == 'SQLI':
        sqli(url)


# Process scan hidden address
def process_scan(scan, url):
    print('Scan - Fuzzing Tool')


def create_banner():
    banner = pyfiglet.figlet_format("Fuzzing Tool", font='slant', justify='center')
    print(Fore.MAGENTA + banner + "\t\t\t\t\t\t\t\t\tTEAM 9")
    print(Fore.RESET)


def main():
    # Print banner
    create_banner()

    # Create the argument parser
    parser = argparse.ArgumentParser(description='Fuzzing Tool - Web vulnerability scanning tool')

    # Add the arguments
    parser.add_argument('-u', '--url', help='URL of the target website', required=True)
    parser.add_argument('-m', '--mode', choices=['SQLI', 'XSS'], help='Type of vulnerability scan')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan hidden address in website')

    # Parse the arguments
    args = parser.parse_args()

    # Perform the scanning logic
    try:
        if args.mode and args.scan:
            print(Fore.RED + "[!]Invalid mode. Choose only one of options: mode or scan")
            print(Fore.RESET)
        elif args.mode:
            process_mode(args.mode, args.url)
        elif args.scan:
            process_scan(args.scan, args.url)
        else:
            print(Fore.RED + "[!]Invalid mode. Choose mode or scan")
            print(Fore.RESET)
    except Exception as e:
        print(Fore.RED + f'[!]{e}')
        print(Fore.RESET)


if __name__ == '__main__':
    main()
