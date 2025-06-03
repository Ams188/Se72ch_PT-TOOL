import sys
import requests
import re
import socket
import json
import argparse
import whois
from dns import zone, resolver, query, exception, rdatatype
from pathlib import Path
from datetime import datetime

class Crt:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"https://crt.sh/?q={domain}"

    def execute(self):
        try:
            response = requests.get(self.url)
            if response.status_code != 200:
                return set()
            subdomains = set()
            for domain in re.findall(br'<TD>.*?</TD>', response.content):
                domain = domain.replace(b'<TD>', b'').replace(b'</TD>', b'')
                if self.domain.encode() in domain:
                    subdomains.update(domain.split(b'<BR>'))
            return {d.decode("utf-8") for d in subdomains}
        except Exception:
            return set()

class waybackmachine:
    def __init__(self, domain):
        self.domain = domain

    def execute(self):
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey"
            response = requests.get(url).text.split('\n')
            subdomains = set()
            for link in response:
                if link:
                    subdomains.add(re.sub(r'^https?://', '', link).split('/')[0].split(':')[0])
            return subdomains
        except Exception:
            return set()

class alienvault_lookup:
    def __init__(self, domain):
        self.domain = domain

    def execute(self):
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            return {entry["hostname"] for entry in json.loads(requests.get(url).text).get("passive_dns", [])}
        except Exception:
            return set()

def verify_subdomains(subdomains):
    verified = []
    for host in subdomains:
        try:
            ip = socket.gethostbyname(host)
            verified.append((host, ip))
        except Exception:
            continue
    return verified

def query_whois(domain):
    try:
        info = whois.whois(domain)
        result = []
        for key, value in info.items():
            if value is None:
                result.append(f"{key.capitalize()}: None")
            elif isinstance(value, list):
                result.append(f"{key.capitalize()}: {', '.join(str(v) for v in value)}")
            else:
                result.append(f"{key.capitalize()}: {value}")
        return result
    except Exception as e:
        return [f"WHOIS error: {e}"]

def get_name_servers(domain):
    try:
        name_servers = resolver.resolve(domain, 'NS')
        return [ns.to_text() for ns in name_servers]
    except Exception as e:
        return [f"Name servers error: {e}"]

def perform_zone_transfer(domain, nameserver):
    try:
        ip = resolver.resolve(str(nameserver), rdtype=rdatatype.A).rrset[0].to_text()
        zone_data = zone.from_xfr(query.xfr(ip, domain, timeout=10))
        return [zone_data[name].to_text(name) for name in zone_data.nodes.keys()]
    except Exception as e:
        print(f"Zone transfer error: {e}")
        return []

def check_dns_records(domain):
    records = []
    try:
        for rtype in ["TXT", f"_dmarc.{domain}"]:
            try:
                dns_records = resolver.resolve(domain if rtype == "TXT" else rtype, "TXT")
                records.extend([record.to_text() for record in dns_records])
            except Exception:
                continue
    except Exception as e:
        records.append(f"DNS records error: {e}")
    return records

def save_results(domain, subdomains, verified, whois_info, name_servers, dns_records):
    output_dir = Path("home/passive")
    output_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "subdomains.txt": sorted(subdomains),
        "ips.txt": [ip for _, ip in verified],
        "whois.txt": whois_info,
        "nameservers.txt": name_servers,
        "dns_records.txt": dns_records
    }

    for file_name, data in files.items():
        file_path = output_dir / file_name
        with open(file_path, "w") as f:
            for item in data:
                f.write(f"{item}\n")

def passive_recon(args):
    domain = args.domain
    
    subdomains = set()
    for source in [Crt(domain), waybackmachine(domain), alienvault_lookup(domain)]:
        subdomains.update(source.execute())
    
    print("Subdomains:")
    for sub in sorted(subdomains):
        print(f"- {sub}")
    
    verified = verify_subdomains(subdomains)
    if verified:
        print("\nIP Addresses:")
        for host, ip in verified:
            print(f"- {host}: {ip}")
    
    print("\nWHOIS:")
    whois_info = query_whois(domain)
    for line in whois_info:
        print(f"- {line}")
    
    print("\nName Servers:")
    name_servers = get_name_servers(domain)
    for ns in name_servers:
        print(f"- {ns}")
    
    if name_servers:
        print("\nZone Transfers:")
        for ns in name_servers:
            perform_zone_transfer(domain, ns)
    
    print("\nDNS Records:")
    dns_records = check_dns_records(domain)
    for record in dns_records:
        print(f"- {record}")
    
    save_results(domain, subdomains, verified, whois_info, name_servers, dns_records)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive reconnaissance tool")
    parser.add_argument("domain", help="Domain for passive reconnaissance")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        print("Use -h or --help to see options")
        sys.exit(1)

    passive_recon(args)
