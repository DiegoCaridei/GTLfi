import re
import subprocess
import time
import sys
import random
import argparse
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from termcolor import colored

# Define LFI errors
lfi_errors = ["root:x:", "bin:x:", "daemon", "syntax", "mysql_", "shutdown", "ftp", "cpanel", "/bin/bash", "/usr/sbin", "www-data", "root:x:0:0:root:", "syslog"]



def print_help():
    options = """
+===================================================================================+
       --url      Provide a single URL for testing
       --urls     Provide a URLs list for testing
       --payloads Provide a list of LFI payloads for testing
       --burp     Provide a Burp Suite intercepted request file
       -p         Specify the parameter to test in the Burp request
       -s         Rate limit to 12 requests per second
       -h         Display help message and exit.
       -f         Use multi-threading with 10 workers for faster scanning
       -d         Sleep duration in seconds between requests

Example: python GTLFI.py --url http://example.com --payloads lfi_payloads.txt -p paramName
+===================================================================================+
"""
    print(colored(options, 'white'))

def random_delay(sleep_seconds):
    if sleep_seconds:
        time.sleep(sleep_seconds)

def scan_url(url, payload, headers):  
    url_components = urlparse(url)
    query_params = parse_qs(url_components.query)

    for key in query_params.keys():
        original_values = query_params[key]

        payload = payload.replace('"', r'\"')

        url_modified = url
        query_params[key] = [payload]
        url_modified = urlunparse((url_components.scheme, url_components.netloc, url_components.path, url_components.params, urlencode(query_params, doseq=True), url_components.fragment))
        query_params[key] = original_values

        command = f'curl -s -i --url "{url_modified}"'
        try:
            output_bytes = subprocess.check_output(command, shell=True)
        except subprocess.CalledProcessError as e:
            continue

        output_str = output_bytes.decode('utf-8', errors='ignore')

        lfi_matches = [error for error in lfi_errors if error in output_str]
        if lfi_matches:
            message = f"\n{colored('LOCAL FILE INCLUSION ERROR FOUND ON', 'white')} {colored(url_modified, 'red')}"
            with open('lfi_errors.txt', 'a') as file:
                file.write(url_modified + '\n')
            for match in lfi_matches:
                print(colored(" Match Words: " + match, 'cyan'))
            print(message)

def scan_burp_request(burp_request, payload, param_name):
    lines = burp_request.splitlines()
    url = lines[0].split()[1]
    headers = {}
    body = ""

    is_body = False
    for line in lines[1:]:
        if line == "":
            is_body = True
            continue
        if is_body:
            body += line + "&"
        else:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    if param_name in body:
        body = re.sub(f"({param_name}=)[^&]*", f"\\1{payload}", body)
    elif param_name in headers.get("Cookie", ""):
        headers["Cookie"] = re.sub(f"({param_name}=)[^;]*", f"\\1{payload}", headers["Cookie"])

    command = f'curl -s -i -X {lines[0].split()[0]} "{url}" -H "{headers}" --data "{body}"'
    try:
        output_bytes = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError as e:
        return

    output_str = output_bytes.decode('utf-8', errors='ignore')

    lfi_matches = [error for error in lfi_errors if error in output_str]
    if lfi_matches:
        message = f"\n{colored('LOCAL FILE INCLUSION ERROR FOUND ON', 'white')} {colored(url, 'red')}"
        with open('lfi_errors.txt', 'a') as file:
            file.write(url + '\n')
        for match in lfi_matches:
            print(colored(" Match Words: " + match, 'cyan'))
        print(message)

def main():
    parser = argparse.ArgumentParser(description="LFI Tool", add_help=False)
    parser.add_argument("--url", help="Provide a single URL for testing", type=str)
    parser.add_argument("--urls", help="Provide a URLs list for testing", type=str)
    parser.add_argument("--payloads", help="Provide a list of LFI payloads for testing", type=str, default="lfi_wordlist.txt")
    parser.add_argument("--burp", help="Provide a Burp Suite intercepted request file", type=str)
    parser.add_argument("-p", "--param", help="Specify the parameter to test in the Burp request", type=str)
    parser.add_argument("-s", "--silent", action="store_true", help="Rate limit to 12 requests per second")
    parser.add_argument("-h", "--help", action="store_true", help="Display help message and exit.")
    parser.add_argument("-f", "--fast", action="store_true", help="Use multi-threading with 10 workers for faster scanning")
    parser.add_argument("-d", "--delay", type=int, help="Sleep duration in seconds between requests")

    args = parser.parse_args()

    if args.help:
        print_help()
        exit()

    print_help()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.urls:
        with open(args.urls, 'r') as f:
            urls.extend(f.read().splitlines())

    with open(args.payloads, 'r') as f:
        payloads = f.read().splitlines()

    # Randomize the order of URLs
    random.shuffle(urls)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate'
    }

    for payload in payloads:
        if args.burp:
            with open(args.burp, 'r') as f:
                burp_request = f.read()
            if args.param:
                scan_burp_request(burp_request, payload, args.param)
            else:
                print(colored("Error: Parameter to test must be specified with -p when using --burp.", "red"))
                exit()
        else:
            for url in urls:
                scan_url(url, payload, headers)
                random_delay(args.delay)

    print("Scanning completed.")

if __name__ == "__main__":
    main()