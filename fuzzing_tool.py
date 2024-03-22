import argparse
from colorama import Fore
from bs4 import BeautifulSoup
import requests
import pyfiglet
import re

# SQL Injection
def sqli_low(url):
    payload = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login'
    }
    payload_levels = {
        1: {'security': 'low', 'seclev_submit': 'Submit'},
        2: {'security': 'medium', 'seclev_submit': 'Submit'},
        3: {'security': 'high', 'seclev_submit': 'Submit'}
    }
    with requests.Session() as c:
        # Login
        r = c.get('http://127.0.0.1/dvwa/login.php')
        token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
        payload['user_token'] = token
        p = c.post('http://127.0.0.1/dvwa/login.php', data=payload)
        
        # Setting security level
        payload_level = payload_levels.get(1, None)
        if payload_level:
            payload_level['user_token'] = token
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_level)
        else:
            print(Fore.RED + "[!]Invalid security level selected. Defaulting to 'low'." + Fore.RESET)
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_levels[1])
        
        # SQLI
        sqli_payloads = []
        with open('/home/kaito/Python/sqli_payloads.txt', 'r') as file:
            for line in file:
                sqli_payload = line[:-1]
                sqli_payloads.append(sqli_payload)
        response = c.get(url)
        soup = BeautifulSoup(response.text, 'html.parser').find_all('input')
        data = {}
        check = False
        print(Fore.YELLOW + f'Target website: {url} - Security Level: {payload_level["security"]}\n' + Fore.RESET)
        payloads_pass = []
        for payload in sqli_payloads:
                print(f'{Fore.GREEN} [+]Testing: {Fore.RESET} {payload}')
                for field in soup:
                    if field['type'].lower() == 'text':
                        data[field['name']] = payload
                        data['Submit'] = 'Submit' 
                response = c.get(url=url, params=data)
                if payload in response.text:
                    payloads_pass.append(payload)
                    check = True
        if check:
            print(Fore.RED + f'\n[**]Payloads pass: \n' + Fore.RESET)
            for payload in payloads_pass:
                print(Fore.GREEN + f'[+]Payload: {payload}' + Fore.RESET)
            print(Fore.RED + '\n[***]The website is vulnerable to SQLI[***]' + Fore.RESET)
        else:
            print(Fore.GREEN + '\n[***]The website may be not vulnerable to SQLI[***]' + Fore.RESET)

def sqli_medium(url):
    payload = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login'
    }
    payload_levels = {
        1: {'security': 'low', 'seclev_submit': 'Submit'},
        2: {'security': 'medium', 'seclev_submit': 'Submit'},
        3: {'security': 'high', 'seclev_submit': 'Submit'}
    }
    with requests.Session() as c:
        # Login
        r = c.get('http://127.0.0.1/dvwa/login.php')
        token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
        payload['user_token'] = token
        p = c.post('http://127.0.0.1/dvwa/login.php', data=payload)
        headers = r.request.headers

        # Setting security level
        payload_level = payload_levels.get(2, None)
        if payload_level:
            payload_level['user_token'] = token
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_level)
        else:
            print(Fore.RED + "[!]Invalid security level selected. Defaulting to 'low'." + Fore.RESET)
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_levels[1])
        
        # SQLI
        sqli_payloads = []
        with open('/home/kaito/Python/sqli_payloads.txt', 'r') as file:
            for line in file:
                sqli_payload = line[:-1]
                sqli_payloads.append(sqli_payload)
        
        response = c.get(url)
        data = {}
        check = False
        payloads_pass = []
        print(Fore.YELLOW + f'Target website: {url} - Security Level: {payload_level["security"]}\n' + Fore.RESET)

        for payload in sqli_payloads:
            print(f'{Fore.GREEN} [+]Testing: {Fore.RESET} {payload}')
            data['id'] = payload
            data['Submit'] = 'Submit' 
            response = c.post(url=url, data=data) 
            if payload in response.text:
                payloads_pass.append(payload)
                check = True
        if check:
            print(Fore.RED + f'\n[**]Payloads pass: \n' + Fore.RESET)
            for payload in payloads_pass:
                print(Fore.GREEN + f'[+]Payload: {payload}' + Fore.RESET)
            print(Fore.RED + '\n[***]The website is vulnerable to SQLI[***]' + Fore.RESET)
        else:
            print(Fore.GREEN + '\n[***]The website may be not vulnerable to SQLI[***]' + Fore.RESET)

# XSS
def xss(url, sec_level):
    payload = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login'
    }

    payload_levels = {
        1: {'security': 'low', 'seclev_submit': 'Submit'},
        2: {'security': 'medium', 'seclev_submit': 'Submit'},
        3: {'security': 'high', 'seclev_submit': 'Submit'}
    }

    with requests.Session() as c:
        # Login
        r = c.get('http://127.0.0.1/dvwa/login.php')
        token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
        payload['user_token'] = token
        p = c.post('http://127.0.0.1/dvwa/login.php', data=payload)

        # Setting security level
        payload_level = payload_levels.get(sec_level, None)
        if payload_level:
            payload_level['user_token'] = token
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_level)
        else:
            print(Fore.RED + "[!]Invalid security level selected. Defaulting to 'low'." + Fore.RESET)
            p = c.post('http://127.0.0.1/dvwa/security.php', data=payload_levels[1])

        # XSS Testing - Reflected
        xss_payloads = []
        with open('/home/kaito/Python/xss_payloads.txt', 'r') as file:
            for line in file:
                xss_payload = line[:-1]
                xss_payloads.append(xss_payload)

        response = c.get(url)
        soup = BeautifulSoup(response.text, 'html.parser').find_all('input')
        data = {}
        check = False
        payloads_pass = []

        print(Fore.YELLOW + f'Target website: {url} - Security Level: {payload_level["security"]}\n' + Fore.RESET)

        for payload in xss_payloads:
                print(f'{Fore.GREEN} [+]Testing: {Fore.RESET} {payload}')
                for field in soup:
                    if field['type'].lower() == 'text':
                        data[field['name']] = payload

                response = c.get(url=url, params=data)
                if payload in response.text:
                    payloads_pass.append(payload)
                    check = True
        if not check:
            print(Fore.GREEN + '\n[***]The website may be not vulnerable to XSS[***]' + Fore.RESET)
        else:
            print(Fore.RED + f'\n[**]Payloads pass: \n' + Fore.RESET)
            for payload in payloads_pass:
                print(Fore.GREEN + f'[+]Payload: {payload}' + Fore.RESET)
            print(Fore.RED + '\n[***]The website is vulnerable to XSS[***]' + Fore.RESET)

# Process mode
def process_mode(mode, url, sec_level):
    if mode == 'XSS':
        xss(url, sec_level)
    elif mode == 'SQLI':
        if sec_level == 1:
            sqli_low(url)
        elif sec_level == 2:
            sqli_medium(url)
        elif sec_level == 3:
            print(Fore.LIGHTBLUE_EX + 'The feature is being updated.' + Fore.RESET)

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
    parser.add_argument('-m', '--mode', choices=['SQLI', 'XSS'], help='Type of vulnerability scan', required=True)
    parser.add_argument('-s', '--sec_level', type=int, choices=[1, 2, 3], help='Security level (1: low, 2: medium, 3: high)', default=1)

    # Parse the arguments
    args = parser.parse_args()

    # Perform the scanning logic
    try:
        process_mode(args.mode, args.url, args.sec_level)
    except Exception as e:
        print(Fore.RED + f'[!]{e}')
        print(Fore.RESET)


if __name__ == '__main__':
    main()
