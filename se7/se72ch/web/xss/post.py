import requests
import os
from urllib.parse import urlparse, parse_qsl, urlencode

# Input files
target_file = "a.txt"
wordlist_file = "listxss.txt"

def detect_protocol(domain):
    return domain  # Retained for compatibility

try:
    with open(target_file, 'r') as file:
        lines = file.read().splitlines()

    if len(lines) < 4:
        print("[ERROR] a.txt must contain at least 4 lines: method, URL, parameter, and cookie/path info.")
        exit()

    method_line = lines[0].strip().upper()
    if method_line != "POST":
        print(f"[ERROR] Only POST method is supported. Found: {method_line}")
        exit()

    domain = lines[1].strip()
    target_param = lines[2].strip()
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

    # التعامل مع السطر السادس إذا كان موجودًا وغير فارغ
    base_params = []
    if len(lines) >= 6 and lines[5].strip():
        base_params = parse_qsl(lines[5].strip(), keep_blank_values=True)

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
    print(f"[INFO] Parameter: {target_param}")
    print(f"[INFO] Cookies: {'USED' if use_cookies else 'Not used'}")
    print(f"[INFO] Generating and testing {len(wordlist)} POST payload(s) for XSS...")

    for idx, word in enumerate(wordlist, 1):
        # تحضير البراميترات
        if base_params:
            payload_params = []
            for k, v in base_params:
                if k == target_param:
                    payload_params.append((k, word))
                else:
                    payload_params.append((k, v))
        else:
            payload_params = [(target_param, word)]

        payload = urlencode(payload_params)

        raw_request = f"POST {path} HTTP/1.1\n"
        raw_request += f"Host: {host}\n"
        raw_request += "User-Agent: python-requests/2.31.0\n"
        raw_request += "Accept-Encoding: gzip, deflate, br\n"
        raw_request += "Accept: */*\n"
        raw_request += "Connection: keep-alive\n"
        raw_request += "Content-Type: application/x-www-form-urlencoded\n"
        if use_cookies:
            raw_request += f"Cookie: {cookies_line}\n"
        raw_request += f"Content-Length: {len(payload)}\n"
        raw_request += "\n"
        raw_request += payload

        # Save to directory
        safe_word = word.replace("/", "_")
        folder_path = os.path.join("w", safe_word)
        os.makedirs(folder_path, exist_ok=True)

        # Write raw request
        request_file = os.path.join(folder_path, "request.txt")
        with open(request_file, 'w', encoding='utf-8') as out:
            out.write(raw_request)

        # تحويل إلى dict للإرسال
        data_payload = dict(payload_params)

        # Send actual POST request
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if use_cookies:
                headers["Cookie"] = cookies_line
            response = requests.post(
                base_url + path, data=data_payload, timeout=5, headers=headers
            )

            # Save response to file
            response_file = os.path.join(folder_path, "response.txt")
            with open(response_file, 'w', encoding='utf-8', errors='ignore') as resp_out:
                resp_out.write(f"HTTP/{response.raw.version} {response.status_code} {response.reason}\n")
                for key, value in response.headers.items():
                    resp_out.write(f"{key}: {value}\n")
                resp_out.write("\n")
                resp_out.write(response.text)

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
