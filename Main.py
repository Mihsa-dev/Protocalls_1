import re
import socket
import subprocess
import requests
from ipaddress import ip_address, IPv4Address


def is_valid_ip(addr):
    try:
        return bool(ip_address(addr))
    except ValueError:
        return False


def get_asn_info(ip):
    if not is_valid_ip(ip) or ip_address(ip).is_private:
        return None, None, None

    try:
        country = None
        provider = None
        asn = None

        url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"

        resp = requests.get(url, timeout=5)

        data = resp.json()

        for rec in data.get('data', {}).get('records', []):
            for attribute in rec:
                key = attribute.get('key', '').lower()
                value = attribute.get('value', '')

                if key == 'origin' and not asn:
                    asn = value.split()[0]
                elif key == 'country' and not country:
                    country = value
                elif key in ['netname', 'descr'] and not provider:
                    provider = value

        if not asn:
            url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"

            resp = requests.get(url, timeout=5)

            data = resp.json()
            asn = data.get('data', {}).get('asns', [None])[0]
        return asn, country, provider

    except Exception as e:
        print(f"Can't receive info for {ip}: {str(e)}")
        return None, None, None


def route(target):
    try:
        if not is_valid_ip(target):
            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                print(f"Can't resolve domain name: {target}")
                return []

        command = ['tracert', '-d', target]

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()
        output = output.decode('cp866', errors='ignore')

        pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = []

        for line in output.split('\n'):
            if '***' in line:
                break

            match = pattern.search(line)

            if match:
                ip = match.group()
                if ip not in ips and ip != target:
                    ips.append(ip)

        return ips

    except Exception as e:
        print(f"Cannot trace: {e}")
        return []


def main():
    target = input("Enter the domain name or IP for tracing: ")
    ips = route(target)

    for ind, ip in enumerate(ips, 1):
        if ip_address(ip).is_private:
            print(f"| {ind} | {ip} | N/A (this IP is private) | N/A | N/A |")
            continue

        asn, country, provider = get_asn_info(ip)

        asn_disp = f"AS{asn}" if asn else "N/A"
        country_disp = country if country else "N/A"
        provider_disp = provider if provider else "N/A"

        print(f"| {ind} | {ip} | {asn_disp} | {provider_disp} | {country_disp} |")


if __name__ == "__main__":
    main()