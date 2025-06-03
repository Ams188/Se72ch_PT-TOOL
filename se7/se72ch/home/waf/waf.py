import sys
import subprocess
import re

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def detect_waf(domain):
    # Ensure URL has https:// prefix
    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = f"https://{domain}"
    else:
        url = domain

    try:
        result = subprocess.run(
            ['wafw00f', url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        clean_output = remove_ansi_codes(result.stdout)

        for line in clean_output.splitlines():
            if line.strip().startswith("[+] The site"):
                print(line.strip())

                match = re.search(r'is behind (.*?)\s*\(', line)
                if match:
                    waf_name = match.group(1).strip()
                else:
                    waf_name = line.split("is behind")[-1].replace("WAF.", "").strip()

                with open("home/waf/waf_detected.txt", "w") as f:
                    f.write(waf_name + "\n")
                return

        print(f"[-] No WAF detected on {url}.")
        with open("waf_detected.txt", "w") as f:
            f.write("Unknown\n")

    except FileNotFoundError:
        print("[-] Make sure wafw00f is installed. Try: pip install wafw00f")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python waf.py <domain>")
        sys.exit(1)

    target_domain = sys.argv[1]
    detect_waf(target_domain)
