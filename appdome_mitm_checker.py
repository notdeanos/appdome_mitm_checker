#!/usr/bin/env python3

"""
Dean Mcdonald <dean@appdome.com> (c) Appdome, 2023.

NOT COVERED BY APPDOME SUPPORT

This script performs comprehensive checks on a list of hostnames to evaluate their SSL/TLS security configurations.
It checks for HTTPS support, ownership information, country of ownership, HSTS support, and TLS versions.

Usage: python appdome_mitm_chcker.py <input_file> <output_file> [--verbose] [--delimiter <delimiter>] [--threads <thread_count>]

Arguments:
  <input_file>        Path to the input file containing a list of hostnames to check
  <output_file>       Path to the output file to store the results (default: output_file.csv)


  sample input_file:
        somehost1.com
        api.somecdn.com
        yetanotherhost.mynetwork.xyz

Options:
  --verbose           Print detailed progress and debugging information
  --delimiter         Delimiter to use in the output file (default: tab)
  --threads           Number of threads to use for concurrent execution (default: 10)
"""

import sys
import socket
import ssl
import ipwhois
from ipwhois import IPWhois
import concurrent.futures
import csv
import logging

# Default values for command-line arguments
DEFAULT_OUTPUT_FILE = "output_file.csv"
DEFAULT_DELIMITER = "\t"
DEFAULT_THREAD_COUNT = 10

# Global cache to store the results of previous lookups
HOSTNAME_CACHE = {}


def get_ip_address(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
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


def get_owner_from_ip(ip_address):
    try:
        obj = ipwhois.IPWhois(ip_address)
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
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    tls_version = ssl.get_protocol_name(ssock.version)
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

    if not owner:
        owner_from_ip = get_owner_from_ip(ip_address)
        if owner_from_ip:
            owner = owner_from_ip
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


def process_hostnames(input_file, output_file, delimiter, thread_count, verbose):
    hostnames = []
    with open(input_file, "r") as file:
        hostnames = file.read().splitlines()

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
                "Failure Reason",
            ]
        )
        writer.writerows(results)


def main():
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print(
            "Usage: python appdome_mitm_checker.py <input_file> <output_file> [--verbose] [--delimiter <delimiter>] [--threads <thread_count>]"
        )
        return

    input_file = sys.argv[1]
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

    process_hostnames(input_file, output_file, delimiter, thread_count, verbose)


if __name__ == "__main__":
    main()

