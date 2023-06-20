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
                    return True, None
                else:
                    return False, "No SSL/TLS certificate found"
    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        return False, str(e)
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def check_hsts_support(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert and "extensions" in cert:
                    extensions = cert["extensions"]
                    if "subjectAltName" in extensions:
                        subject_alt_name = extensions["subjectAltName"]
                        for entry in subject_alt_name:
                            if entry[0] == "DNS" and entry[1] == hostname:
                                return True, None
                    return False, "HSTS not supported"
                else:
                    return False, "No SSL/TLS certificate found"
    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        return False, str(e)
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def check_tls_version(hostname, tls_version):
    try:
        context = ssl.create_default_context()
        context.set_ciphers("DEFAULT@SECLEVEL=1")
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options &= ~ssl.OP_NO_TLSv1_2
        context.minimium_version = tls_version

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, None
    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        return False, str(e)
    except socket.timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def process_hostname(hostname, delimiter, verbose):
    result = []
    result.append(hostname)

    # Check HTTPS support
    success, failure_reason = check_https_support(hostname)
    if success:
        result.append("HTTPS Supported")
    else:
        result.append("HTTPS Not Supported")
        result.append(failure_reason)
        return result

    # Check HSTS support
    success, failure_reason = check_hsts_support(hostname)
    if success:
        result.append("HSTS Supported")
    else:
        result.append("HSTS Not Supported")
        result.append(failure_reason)

    # Check TLS versions
    tls_versions = ["TLSv1.2", "TLSv1.3"]
    for tls_version in tls_versions:
        success, failure_reason = check_tls_version(hostname, tls_version)
        if success:
            result.append(tls_version + " Supported")
        else:
            result.append(tls_version + " Not Supported")
            result.append(failure_reason)

    return result


def print_result(result):
    line_output = "\t".join(result)
    print(line_output)


def process_hostnames(input_file, output_file, delimiter, thread_count, verbose):
    # Read hostnames from input file
    hostnames = []
    with open(input_file, "r") as file:
        reader = csv.reader(file, delimiter=delimiter)
        for row in reader:
            if row:
                hostnames.append(row[0])

    # Process hostnames concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = []
        for hostname in hostnames:
            futures.append(executor.submit(process_hostname, hostname, delimiter, verbose))

        # Print results as they become available
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print_result(result)
            sys.stdout.flush()

            # Write to output file
            with open(output_file, "a") as file:
                writer = csv.writer(file, delimiter=delimiter)
                writer.writerow(result)


def main():
    # Parse command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python appdome_mitm_checker.py <input_file> <output_file> [--verbose] [--delimiter <delimiter>] [--threads <thread_count>]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    delimiter = DEFAULT_DELIMITER
    thread_count = DEFAULT_THREAD_COUNT
    verbose = False

    if "--verbose" in sys.argv:
        verbose = True

    if "--delimiter" in sys.argv:
        delimiter_index = sys.argv.index("--delimiter")
        delimiter = sys.argv[delimiter_index + 1]

    if "--threads" in sys.argv:
        threads_index = sys.argv.index("--threads")
        thread_count = int(sys.argv[threads_index + 1])

    # Set up logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=log_level)

    # Clear output file
    with open(output_file, "w"):
        pass

    # Process hostnames
    process_hostnames(input_file, output_file, delimiter, thread_count, verbose)


if __name__ == "__main__":
    main()

