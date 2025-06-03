#!/usr/bin/env python3
import subprocess
import re
import os
import sys
import threading
from dns import resolver

### --- NMAP SCAN --- ###
def run_nmap(domain, mode):
    try:
        scan_dir = "results/scan"
        os.makedirs(scan_dir, exist_ok=True)

        if mode == "fast":
            print(f"[+] Running FAST scan on: {domain}")
            args = ["nmap", "-T5", "-F", domain]
        elif mode == "full":
            print(f"[+] Running FULL scan on: {domain}")
            args = ["nmap", "-A", "-T1", domain]
        else:
            print("[-] Invalid mode.")
            return

        result = subprocess.run(args, capture_output=True, text=True)
        output = result.stdout

        if mode == "full":
            os_info = re.findall(r"OS details: (.*)", output)
            with open(f"{scan_dir}/os.txt", "w") as f:
                f.write(os_info[0] if os_info else "Not detected")

        open_ports = re.findall(r"^(\d+/\w+).*open", output, re.MULTILINE)
        with open(f"{scan_dir}/open_ports.txt", "w") as f:
            for port in open_ports:
                f.write(port + "\n")

        service_info = re.findall(r"^(\d+/\w+)\s+open\s+(\S+)\s+(.*)$", output, re.MULTILINE)
        with open(f"{scan_dir}/services.txt", "w") as f:
            for port, service, version in service_info:
                f.write(f"[port: {port}] [service: {service}] [version: {version}]\n")

        print("[+] Scan results saved in 'results/scan/'")
    except Exception as e:
        print(f"[-] Nmap error: {e}")

### --- DNS BRUTEFORCE --- ###
class DNSBrute:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.wordlists = {
            'fast': './DNSlist_short.txt',
            'full': './DNSlist_long.txt'
        }

    def listprep(self, wordlist, numOfChunks):
        for i in range(0, len(wordlist), numOfChunks):
            yield wordlist[i:i + numOfChunks]

    def resolvehost(self, listt):
        for word in listt:
            try:
                hostname = f"{word.strip()}.{self.domain}"
                res = resolver.Resolver()
                answers = res.resolve(hostname)
                if answers:
                    ip_addresses = [rdata.address for rdata in answers]
                    print(f"[+] Found: {hostname} - IPs: {', '.join(ip_addresses)}")
                    self.subdomains.append([hostname, ', '.join(ip_addresses)])
            except:
                pass

    def BruteForce(self, threads_count, wordlist):
        threads = []
        try:
            with open(wordlist, 'r') as f:
                words = f.readlines()
        except Exception as e:
            print(f"[-] Wordlist error: {e}")
            sys.exit(1)

        if threads_count <= 0 or threads_count > len(words):
            threads_count = 10

        chunk_size = len(words) // threads_count
        for chunk in self.listprep(words, chunk_size):
            threads.append(threading.Thread(target=self.resolvehost, args=(chunk,), daemon=True))

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def save_results(self):
        brute_dir = "results/bruteforce"
        os.makedirs(brute_dir, exist_ok=True)
        with open(f'{brute_dir}/domains.txt', 'w') as f_domains:
            for sub, _ in self.subdomains:
                f_domains.write(sub + '\n')
        with open(f'{brute_dir}/ips.txt', 'w') as f_ips:
            for _, ips in self.subdomains:
                for ip in ips.split(', '):
                    f_ips.write(ip + '\n')

    def execute(self, mode='fast', threads=10):
        if mode not in self.wordlists:
            print("[-] Invalid mode for bruteforce.")
            sys.exit(1)
        self.BruteForce(threads, self.wordlists[mode])
        self.save_results()
        return self.subdomains

### --- MAIN ENTRY --- ###
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Combined Recon Tool (Nmap + DNS Bruteforce)")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--mode", choices=["fast", "full"], default="fast", help="Mode: fast=short and quick, full=long and thorough")
    parser.add_argument("--threads", type=int, default=10, help="Thread count for bruteforce")

    args = parser.parse_args()

    # Run Nmap scan
    run_nmap(args.domain, args.mode)

    # Run DNS brute
    brute = DNSBrute(args.domain)
    brute.execute(mode=args.mode, threads=args.threads)

    print("\n[+] Completed both Nmap and Subdomain Bruteforce.")

if __name__ == "__main__":
    main()
