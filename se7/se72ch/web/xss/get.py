import requests
import os
from urllib.parse import urlparse

# Input files
target_file = "a.txt"
wordlist_file = "listxss.txt"

def detect_protocol(domain):
    # Retained for compatibility; not used
    return domain

try:
    with open(target_file, 'r') as file:
        lines = file.read().splitlines()

    if len(lines) < 4:
        print("[ERROR] a.txt must contain at least 4 lines: method, URL, parameter, and cookie/path info.")
        exit()

    method_line = lines[0].strip().upper()
    if method_line != "GET":
        print(f"[ERROR] Only GET method is supported. Found: {method_line}")
        exit()

    domain = lines[1].strip()
    param = lines[2].strip()
    fourth_line = lines[3].strip()

    if fourth_line.lower() == "optional":
        if len(lines) < 5:
            print("[ERROR] Missing path line. If cookies are 'optional', a fifth line for path is required.")
            exit()
        use_cookies = False
        cookies_line = ""
        path = lines[4].strip()
    else:
        use_cookies = True
        cookies_line = fourth_line
        path = lines[4].strip() if len(lines) >= 5 else "/"

    parsed = urlparse(domain)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc

    # Read wordlist
    with open(wordlist_file, 'r') as wf:
        wordlist = [line.strip() for line in wf if line.strip()]
    if not wordlist:
        print("[ERROR] listxss.txt is empty.")
        exit()

    print(f"[INFO] Base URL: {base_url}")
    print(f"[INFO] Path: {path}")
    print(f"[INFO] Parameter: {param}")
    print(f"[INFO] Cookies: {'USED' if use_cookies else 'Not used'}")
    print(f"[INFO] Generating and testing {len(wordlist)} GET payload(s) for XSS...")

    for idx, word in enumerate(wordlist, 1):
        # Build full request path
        full_path = f"{path}?{param}={word}"
        raw_request = f"GET {full_path} HTTP/1.1\n"
        raw_request += f"Host: {host}\n"
        raw_request += "User-Agent: python-requests/2.31.0\n"
        raw_request += "Accept-Encoding: gzip, deflate, br\n"
        raw_request += "Accept: */*\n"
        raw_request += "Connection: keep-alive\n"
        if use_cookies:
            raw_request += f"Cookie: {cookies_line}\n"
        raw_request += "\n"

        # Save to directory
        safe_word = word.replace("/", "_")
        folder_path = os.path.join("w", safe_word)
        os.makedirs(folder_path, exist_ok=True)

        # Write raw request
        request_file = os.path.join(folder_path, "request.txt")
        with open(request_file, 'w', encoding='utf-8') as out:
            out.write(raw_request)

        # Send actual request
        try:
            headers = {}
            if use_cookies:
                headers["Cookie"] = cookies_line
            response = requests.get(
                base_url + path, params={param: word}, timeout=5, headers=headers
            )

            if "hacked_by_se72ch" in response.text:
                print(f"[🎯] SUCCESS with payload: {word}")
            else:
                print(f"[❌] No success indicator for payload: {word}")

        except requests.RequestException as e:
            print(f"[ERROR] Request failed for payload '{word}': {e}")

    print(f"[🏁] Finished. Requests saved in folders under: {os.path.abspath('w')}")

except FileNotFoundError as e:
    print(f"[ERROR] Missing file: {e.filename}")
except Exception as e:
    print(f"[ERROR] {str(e)}")
