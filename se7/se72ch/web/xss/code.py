import requests
from bs4 import BeautifulSoup
from faker import Faker
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime
import os
import glob

fake = Faker()

def parse_cookies(cookie_string):
    cookies = {}
    if cookie_string and cookie_string.lower() != "non":
        for cookie in cookie_string.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies[key] = value
    return cookies

def generate_field_value(field_name, input_type):
    field_name = field_name.lower() if field_name else ""
    if input_type == "text" or input_type == "search":
        if "name" in field_name: return fake.name()
        if "address" in field_name: return fake.address().replace("\n", ", ")
        if "city" in field_name: return fake.city()
        if "country" in field_name: return fake.country()
        if "website" in field_name or "url" in field_name: return fake.url()
        return fake.word()
    if input_type == "email" or "email" in field_name: return fake.email()
    if input_type == "password" or "password" in field_name: return fake.password(length=12)
    if input_type in ["number", "tel"] or "phone" in field_name or "age" in field_name:
        if "phone" in field_name: return fake.phone_number()
        if "age" in field_name: return str(random.randint(18, 80))
        return str(random.randint(1, 1000))
    if input_type == "checkbox": return random.choice(["on", None])
    if input_type == "radio": return fake.word()
    if input_type == "textarea": return fake.text(max_nb_chars=200)
    return fake.word()

def log_request_response(log_dir, request, response, method, action_url, form_data):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(log_dir, f"request_{timestamp}.txt")
    os.makedirs(log_dir, exist_ok=True)
    
    parsed_url = urlparse(action_url)
    path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
    request_line = f"{method.upper()} {path} HTTP/1.1"
    headers = request.headers.copy()
    headers["Host"] = parsed_url.netloc
    body = ""
    if method.lower() == "post" and form_data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = "&".join(f"{key}={requests.utils.quote(str(value))}" for key, value in form_data.items() if value)
        headers["Content-Length"] = str(len(body.encode("utf-8")))
    
    request_text = f"{request_line}\n"
    for key, value in headers.items():
        request_text += f"{key}: {value}\n"
    if request.cookies:
        request_text += f"Cookie: {';'.join(f'{k}={v}' for k, v in request.cookies.items())}\n"
    request_text += "\n" + body if body else ""
    
    response_line = f"HTTP/1.1 {response.status_code} {response.reason}"
    response_text = f"{response_line}\n"
    for key, value in response.headers.items():
        response_text += f"{key}: {value}\n"
    response_text += "\n" + response.text
    
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(request_text)
        f.write("\n\n==========\n\n")
        f.write(response_text)

def write_summary_file(request_type, start_url, first_param, cookie_data, action_path, payload):
    with open("a.txt", "w", encoding="utf-8") as f:
        f.write(f"{request_type or 'N/A'}\n")
        f.write(f"{start_url}\n")
        f.write(f"{first_param or 'N/A'}\n")
        f.write(f"{cookie_data if cookie_data.lower() != 'non' else 'optional'}\n")
        f.write(f"{action_path or 'N/A'}\n")
        f.write(f"{payload or 'N/A'}")

def fill_and_submit_form(url, form, headers, cookies, log_dir):
    form_data = {}
    action = form.get("action", "")
    method = form.get("method", "get").lower()
    
    action_url = urljoin(url, action) if action else url
    parsed_action = urlparse(action_url)
    action_path = parsed_action.path + (f"?{parsed_action.query}" if parsed_action.query else "")
    
    first_param = None
    inputs = form.find_all(["input", "textarea"])
    for input_field in inputs:
        field_name = input_field.get("name") or input_field.get("id") or ""
        input_type = input_field.get("type", "text").lower()
        if input_type == "submit": continue
        if input_type == "hidden":
            value = input_field.get("value", "")
            if value:
                form_data[field_name] = value
            continue
        if not first_param and input_type not in ["email", "number", "tel"] and not any(x in field_name.lower() for x in ["email", "website", "url", "phone", "age"]):
            first_param = field_name
        value = generate_field_value(field_name, input_type)
        if value:
            form_data[field_name] = value

    selects = form.find_all("select")
    for select in selects:
        field_name = select.get("name") or select.get("id") or ""
        options = select.find_all("option")
        if options:
            value = random.choice([opt.get("value") or opt.text for opt in options])
            form_data[field_name] = value
            if not first_param and not any(x in field_name.lower() for x in ["email", "website", "url", "phone", "age"]):
                first_param = field_name

    payload = ""
    if method == "post" and form_data:
        payload = "&".join(f"{key}={requests.utils.quote(str(value))}" for key, value in form_data.items() if value)
    
    if form_data:
        try:
            if method == "post":
                response = requests.post(action_url, data=form_data, headers=headers, cookies=cookies)
            else:
                response = requests.get(action_url, params=form_data, headers=headers, cookies=cookies)
            log_request_response(log_dir, requests.Request(method.upper(), action_url, headers=headers, cookies=cookies, data=form_data if method == "post" else None), response, method, action_url, form_data)
            return method.upper(), first_param, action_path, payload
        except requests.exceptions.RequestException as e:
            error_response = type("Response", (), {"status_code": "Error", "url": action_url, "text": str(e), "headers": {}, "reason": "Request Failed"})()
            log_request_response(log_dir, requests.Request(method.upper(), action_url, headers=headers, cookies=cookies, data=form_data if method == "post" else None), error_response, method, action_url, form_data)
            return method.upper(), first_param, action_path, payload
    return None, None, None, None

def process_page(url, cookies, cookie_data, log_dir):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, cookies=cookies)
        response.raise_for_status()
        log_request_response(log_dir, requests.Request("GET", url, headers=headers, cookies=cookies), response, "get", url, {})
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        request_type, first_param, action_path, payload = None, None, None, None
        if forms:
            for form in forms:
                rt, fp, ap, pl = fill_and_submit_form(url, form, headers, cookies, log_dir)
                if rt and not request_type:
                    request_type, first_param, action_path, payload = rt, fp, ap, pl
        write_summary_file(request_type, url, first_param, cookie_data, action_path, payload)
    except requests.exceptions.RequestException as e:
        error_response = type("Response", (), {"status_code": "Error", "url": url, "text": str(e), "headers": {}, "reason": "Request Failed"})()
        log_request_response(log_dir, requests.Request("GET", url, headers=headers, cookies=cookies), error_response, "get", url, {})
        write_summary_file(None, url, None, cookie_data, None, None)

def main():
    try:
        with open("data.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()
            if len(lines) < 2:
                print("Error: data.txt must contain at least two lines (URL and cookie data).")
                return
            
            url = lines[0].strip()
            cookie_data = lines[1].strip()
            
            cookies = parse_cookies(cookie_data)
            log_dir = "request_logs"
            process_page(url, cookies, cookie_data, log_dir)
            
    except FileNotFoundError:
        print("Error: data.txt file not found.")
    except Exception as e:
        print(f"Error reading data.txt: {e}")

if __name__ == "__main__":
    main()
