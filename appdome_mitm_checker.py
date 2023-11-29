#!/usr/bin/env python3

"""
Dean Mcdonald <dean@appdome.com> (c) Appdome, 2023.

NOT COVERED BY APPDOME SUPPORT

This script performs comprehensive checks on a list of hostnames to evaluate their SSL/TLS security configurations.
It checks for HTTPS support, ownership information, country of ownership, HSTS support, and TLS versions.

Typical use case would be checking a list of hosts that trigger Appdome MiTM (Man-in-the-Middle) warnings. Most useful when there are a lot of hosts to check.

Usage: python3 appdome_mitm_chcker.py <input_file> <output_file> [--verbose] [--delimiter <delimiter>] [--threads <thread_count>]

Arguments:
  <input_file>        Path to the input file containing a list of hostnames or IP addresses (IPv4 & IPv6 supported), or a spreadsheet with 'Host: xxx' entries.
  <output_file>       Path to the output file to store the results (default: output_file.csv)

  sample input_file (can be FQDN or IPv4/IPv6 address, or a spreadsheet):
        somehost1.com
        202.1.46.9
        api.somecdn.com
        2404:6800:4006:80f::200e
        yetanotherhost.mynetwork.xyz

Options:
  --verbose           Print detailed progress and debugging information
  --delimiter         Delimiter to use in the output file (default: tab)
  --threads           Number of threads to use for concurrent execution (default: 10)

Required Python packages:
 - ipwhois: Used for IP address and ownership lookups
   Install with: pip install ipwhois
 - pandas: Used for reading data from spreadsheets
   Install with: pip install pandas
 - socket: Standard library module for network interface
 - ssl: Standard library module for handling SSL/TLS connections
 - concurrent.futures: Standard library module for concurrent execution
 - csv: Standard library module for reading and writing CSV files
 - logging: Standard library module for logging
 - urllib.parse: Standard library module for URL parsing
 - argparse: Standard library module for parsing command-line options
 - signal: Standard library module for handling Unix signals

"""

import sys
import os
import re
import socket
import ssl
import ipwhois
from ipwhois import IPWhois
import concurrent.futures
import csv
import logging
from urllib.parse import urlparse
import argparse
import signal
import pandas as pd
import json

# Default values for command-line arguments
DEFAULT_OUTPUT_FILE = "output_file.csv"
DEFAULT_DELIMITER = "\t"
DEFAULT_THREAD_COUNT = 10

# Global cache to store the results of previous lookups
HOSTNAME_CACHE = {}

def sanitize_hostname(hostname):
    # Keep only valid characters for domain names
    hostname = re.sub(r'[^a-zA-Z0-9.-]', '', hostname)
    return hostname

def remove_url_prefix(hostname):
    if hostname.startswith("http://"):
        return hostname[7:]
    elif hostname.startswith("https://"):
        return hostname[8:]
    else:
        return hostname

def remove_url_path(hostname):
    parsed_url = urlparse(hostname)
    return parsed_url.netloc

def get_ip_address(hostname):
    try:
        ip_addresses = socket.getaddrinfo(hostname, None)
        for addrinfo in ip_addresses:
            ip_version, _, _, _, sockaddr = addrinfo
            if ip_version == socket.AF_INET or ip_version == socket.AF_INET6:
                ip_address = sockaddr[0]
                return ip_address
    except (socket.gaierror, UnicodeError) as e:
        logging.warning(f'Error resolving hostname "{hostname}": {str(e)}')
        return None

def get_owner(ip_address):
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        if 'asn_description' in result:
            owner = result['asn_description']
            return owner
    except Exception:
        return None

def get_country(ip_address):
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_whois()
        if 'asn_country_code' in result:
            country = result['asn_country_code']
            return country
    except Exception:
        return None

def check_https_support(hostname):
    try:
        context = ssl.create_default_context()
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    return True, tls_version
                else:
                    return False, "No SSL/TLS certificate found"
    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        return False, str(e)
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

def process_hostname(hostname, total_hosts, verbose):
    if hostname in HOSTNAME_CACHE:
        return HOSTNAME_CACHE[hostname]

    ip_address = get_ip_address(hostname)
    resolved_domain = ""
    country = ""
    owner = None
    https_support = "Failed"
    tls_version = ""
    failure_reason = ""

    if ip_address:
        owner = get_owner(ip_address)
        if owner:
            country = get_country(ip_address)
            resolved_domain = socket.getfqdn(hostname)
            supports_https, failure_reason = check_https_support(hostname)
            if supports_https:
                if isinstance(supports_https, str):
                    https_support = "Passed"
                    tls_version = supports_https
                else:
                    https_support = "Passed"

    if owner:
        line_output = [hostname, ip_address, country, resolved_domain, owner, https_support, tls_version, failure_reason]
    else:
        line_output = [
            hostname,
            "IP address not found",
            country,
            resolved_domain,
            "Owner information not found",
            https_support,
            tls_version,
            failure_reason,
        ]

    HOSTNAME_CACHE[hostname] = line_output

    completed_hosts = len(HOSTNAME_CACHE)
    percentage_complete = (completed_hosts / total_hosts) * 100

    if verbose:
        logging.info(
            f"\rProgress: {completed_hosts}/{total_hosts} hosts checked ({percentage_complete:.2f}%) - {hostname}"
        )

    return line_output

# New function to read hostnames from a spreadsheet
def read_hostnames_from_spreadsheet(file_path):
    try:
        df = pd.read_excel(file_path)  # Reading the spreadsheet into a DataFrame
        hostnames_set = set()  # Using a set to avoid duplicates

        # Regex pattern to find 'Host: <hostname>'
        pattern = re.compile(r"Host:\s+([^\s]+)")

        for value in df.to_numpy().flatten():  # Flattening the DataFrame to iterate over all cells
            if isinstance(value, str):
                # Search for the 'Host:' pattern and extract the hostname
                match = pattern.search(value)
                if match:
                    hostname = match.group(1).strip()  # Extract the hostname
                    if hostname not in hostnames_set:  # Check if the hostname is already in the set
                        hostnames_set.add(hostname)  # Add the hostname to the set

        return list(hostnames_set)  # Convert the set back to a list to return
    except Exception as e:
        logging.error(f"Error reading spreadsheet: {e}")
        return []

def process_hostnames(input_file, output_file, delimiter, thread_count, verbose, hostnames=None):
    if hostnames is None:
        with open(input_file, "r") as file:
            hostnames = file.read().splitlines()

    hostnames = [remove_url_prefix(hostname) for hostname in hostnames]
    total_hosts = len(hostnames)

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = []
        for hostname, result in zip(
            hostnames,
            executor.map(
                process_hostname, hostnames, [total_hosts] * total_hosts, [verbose] * total_hosts
            ),
        ):
            results.append(result)

    write_output_to_file(output_file, delimiter, results)

def write_output_to_file(output_file, delimiter, results):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file, delimiter=delimiter)
        writer.writerow(
            [
                "Hostname",
                "Resolved IP",
                "Country Code",
                "Resolved Domain",
                "Provider Owner",
                "HTTPS Check",
                "TLS Version",
                "Failure Reason (if any)",
            ]
        )
        writer.writerows(results)

def print_output_file(output_file):
    with open(output_file, "r") as file:
        print(file.read())

def main():
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print(
            "Usage: python appdome_mitm_checker.py <input_file or hostname(s)> <output_file> [--verbose] [--delimiter <delimiter>] [--threads <thread_count>]"
        )
        return

    input_arg = sys.argv[1]
    output_file = DEFAULT_OUTPUT_FILE
    delimiter = DEFAULT_DELIMITER
    thread_count = DEFAULT_THREAD_COUNT
    verbose = False

    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

    if "--verbose" in sys.argv:
        verbose = True

    if "--delimiter" in sys.argv:
        delimiter_index = sys.argv.index("--delimiter")
        delimiter = sys.argv[delimiter_index + 1]

    if "--threads" in sys.argv:
        threads_index = sys.argv.index("--threads")
        try:
            thread_count = int(sys.argv[threads_index + 1])
        except ValueError:
            print("Error: Invalid thread count specified.")
            sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

    if os.path.isfile(input_arg):
        if input_arg.lower().endswith(('.xls', '.xlsx')):  # Check if input file is a spreadsheet
            hostnames = read_hostnames_from_spreadsheet(input_arg)
        else:
            with open(input_arg, "r") as file:
                hostnames = file.read().splitlines()
        process_hostnames(None, output_file, delimiter, thread_count, verbose, hostnames)
    else:
        hostnames = [h.strip() for h in re.split('[ ,]', input_arg)]
        process_hostnames(None, output_file, delimiter, thread_count, verbose, hostnames)

    if verbose:
        print_output_file(output_file)

# Modify the process_hostnames to accept an optional hostnames list
def process_hostnames(input_file, output_file, delimiter, thread_count, verbose, hostnames=None):
    if hostnames is None:
        with open(input_file, "r") as file:
            hostnames = file.read().splitlines()

    hostnames = [remove_url_prefix(hostname) for hostname in hostnames]
    total_hosts = len(hostnames)

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = []
        for hostname, result in zip(
            hostnames,
            executor.map(
                process_hostname, hostnames, [total_hosts] * total_hosts, [verbose] * total_hosts
            ),
        ):
            results.append(result)

    write_output_to_file(output_file, delimiter, results)

# Add a signal handler
def signal_handler(sig, frame):
    print("\nExecution interrupted. Cleaning up...")
    # You can perform any necessary cleanup operations here before exiting
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    main()

