#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import re
import subprocess
import os
import sys
import shlex
import time
import urllib.parse

# Initialize root window
root = tk.Tk()
root.title("DarkPulse - Ethical Hacking Tool")
root.geometry("800x600")
root.configure(bg="#1A1A1A")

# Configure ttk style for advanced dark theme
style = ttk.Style()
style.theme_use('clam')

# Custom styles with glow and futuristic effects
style.configure('TEntry', fieldbackground='#2A2A2A', foreground='#FFFFFF', bordercolor='#8B0000', padding=8,
                font=('Consolas', 12, 'bold'), relief="flat")
style.map('TEntry', bordercolor=[('focus', '#FF4040'), ('!focus', '#8B0000')])
style.configure('TCombobox', fieldbackground='#2A2A2A', foreground='#FFFFFF', background='#2A2A2A', 
                arrowcolor='#FF4040', font=('Consolas', 12, 'bold'), bordercolor='#8B0000')
style.map('TCombobox', fieldbackground=[('focus', '#3A3A3A'), ('!focus', '#2A2A2A')])
style.configure('TButton', background='#8B0000', foreground='#FFFFFF', padding=8, font=('Orbitron', 12, 'bold'),
                bordercolor='#FF4040', relief="flat")
style.map('TButton', background=[('active', '#FF4040'), ('!active', '#8B0000')],
          foreground=[('active', '#FFFFFF'), ('!active', '#FFFFFF')])
style.configure('TCheckbutton', background='#1A1A1A', foreground='#FF4040', font=('Orbitron', 11), indicatorcolor='#8B0000')
style.map('TCheckbutton', indicatorcolor=[('selected', '#FF4040'), ('!selected', '#8B0000')])
style.configure('TRadiobutton', background='#1A1A1A', foreground='#FF4040', font=('Orbitron', 11), indicatorcolor='#8B0000')
style.map('TRadiobutton', indicatorcolor=[('selected', '#FF4040'), ('!selected', '#8B0000')])

# ======= REGEX AND TLDs =========
pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$'
ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?$'
common_tlds = [
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.info', '.biz', '.io', '.co', '.me', '.tv', '.us', '.uk',
    '.ca', '.de', '.jp', '.fr', '.au', '.ru', '.ch', '.it',
    '.nl', '.se', '.no', '.es', '.in', '.cn', '.br', '.za',
    '.mx', '.ae', '.sa', '.pt', '.pl', '.gr', '.cz', '.sk',
    '.fi', '.dk', '.be', '.at', '.nz', '.tr', '.ir', '.kr',
    '.hk', '.tw', '.vn', '.sg', '.id', '.cl', '.ar', '.pe',
    '.my', '.ph', '.ng', '.ke', '.gh', '.pk', '.bd', '.mod',
    '.kz', '.by', '.ua', '.ro', '.bg', '.lt', '.lv', '.ee',
    '.th', '.qa', '.bh', '.om', '.kw', '.il', '.eg', '.ma',
    '.tn', '.dz', '.is', '.al', '.am', '.ge', '.az', '.md',
    '.tv', '.fm', '.cc', '.la', '.ai', '.gg', '.io', '.sh',
    '.ly', '.to', '.ws', '.sc', '.cd', '.su', '.rs', '.si'
]

# ======= PAGE MANAGER =========
pages = {}
def show_page(page_name):
    for name, page in pages.items():
        page.pack_forget()
    pages[page_name].pack(fill="both", expand=True)

# ======= NAVIGATION BAR =========
navbar = tk.Frame(root, bg="#0F0F0F", height=50, relief="raised", borderwidth=2)
navbar.pack(side="top", fill="x")

btn_home = tk.Button(navbar, text="Home", bg="#0F0F0F", fg="#FF4040", relief="flat", font=("Orbitron", 14, "bold"),
                     activebackground="#FF4040", activeforeground="#FFFFFF", command=lambda: show_page("main"),
                     highlightthickness=2, highlightbackground="#8B0000", highlightcolor="#FF4040")
btn_home.pack(side="left", padx=20, pady=10)

btn_exploit = tk.Button(navbar, text="Exploit", bg="#0F0F0F", fg="#FF4040", relief="flat", font=("Orbitron", 14, "bold"),
                        activebackground="#FF4040", activeforeground="#FFFFFF", command=lambda: show_page("exploit"),
                        highlightthickness=2, highlightbackground="#8B0000", highlightcolor="#FF4040")
btn_exploit.pack(side="left", padx=20, pady=10)

btn_result = tk.Button(navbar, text="Output", bg="#0F0F0F", fg="#FF4040", relief="flat", font=("Orbitron", 14, "bold"),
                       activebackground="#FF4040", activeforeground="#FFFFFF", command=lambda: show_page("result"),
                       highlightthickness=2, highlightbackground="#8B0000", highlightcolor="#FF4040")
btn_result.pack(side="left", padx=20, pady=10)

# ======= COMMANDS =========
def command1(domain):
    try:
        result = subprocess.run(["python3", "home/passive/passive_scan.py", domain],
                                capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[Error] Passive Scan failed:\n{e.stderr}"
    except FileNotFoundError:
        return "[Error] passive_scan.py not found. Check path."

def command2(domain, sub_option, threads="10"):
    try:
        script_path = os.path.abspath("home/active/combined_scan/combined_scan.py")
        working_dir = os.path.dirname(script_path)
        print(f"[DEBUG] command2: script_path={script_path}, working_dir={working_dir}", file=sys.stderr)

        if not os.path.isfile(script_path):
            return f"[Error] combined_scan.py not found at: {script_path}", {}

        wordlist_dir = working_dir
        wordlists = ['DNSlist_short.txt', 'DNSlist_long.txt']
        for wl in wordlists:
            if not os.path.isfile(os.path.join(wordlist_dir, wl)):
                return f"[Error] Wordlist {wl} not found in {wordlist_dir}", {}

        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        except FileNotFoundError:
            return "[Error] nmap is not installed or not in PATH.", {}

        mode = "fast" if sub_option.lower() == "short" else "full"
        args = ["python3", script_path, domain, "--mode", mode]
        if threads and threads.isdigit() and int(threads) > 0:
            args.extend(["--threads", threads])
        else:
            return "[Error] Invalid threads value. Must be a positive integer.", {}

        print(f"[DEBUG] command2: Running command: {shlex.join(args)}", file=sys.stderr)

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=True,
            cwd=working_dir,
            env=os.environ.copy()
        )

        output_files = {}
        scan_dir = os.path.join(working_dir, "results", "scan")
        brute_dir = os.path.join(working_dir, "results", "bruteforce")

        for file_name in ["open_ports.txt", "services.txt", "os.txt"]:
            file_path = os.path.join(scan_dir, file_name)
            try:
                if os.path.isfile(file_path):
                    with open(file_path, "r") as f:
                        content = f.read().strip()
                        output_files[file_name] = content if content else f"[Empty] {file_name}"
                else:
                    output_files[file_name] = f"[Not Found] {file_name}"
            except Exception as e:
                output_files[file_name] = f"[Error] Failed to read {file_name}: {str(e)}"

        for file_name in ["domains.txt", "ips.txt"]:
            file_path = os.path.join(brute_dir, file_name)
            try:
                if os.path.isfile(file_path):
                    with open(file_path, "r") as f:
                        content = f.read().strip()
                        output_files[file_name] = content if content else f"[Empty] {file_name}"
                else:
                    output_files[file_name] = f"[Not Found] {file_name}"
            except Exception as e:
                output_files[file_name] = f"[Error] Failed to read {file_name}: {str(e)}"

        return result.stdout or "[Info] No output from active scan.", output_files
    except subprocess.CalledProcessError as e:
        return (
            f"[Error] Active Scan Failed:\n"
            f"Command: {shlex.join(args)}\n"
            f"Exit Code: {e.returncode}\n"
            f"Stderr: {e.stderr or 'No stderr output'}\n"
            f"Stdout: {e.stdout or 'No stdout output'}"
        ), {}
    except Exception as e:
        return f"[Error] Unexpected error in Active Scan:\n{str(e)}", {}

def command3(domain):
    try:
        result = subprocess.run(["python3", "home/waf/waf.py", domain],
                                capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[Error] WAF Detection Failed:\n{e.stderr}"
    except FileNotFoundError:
        return "[Error] waf.py not found. Check path."

# ======= RESULT PAGE =========
result_frame = tk.Frame(root, bg="#1A1A1A")
pages["result"] = result_frame

result_title = tk.Label(result_frame, text="Scan Results", font=("Orbitron", 18, "bold"), bg="#1A1A1A", fg="#FF4040",
                        highlightthickness=2, highlightbackground="#8B0000")
result_title.pack(pady=20)

result_text_frame = tk.Frame(result_frame, bg="#2A2A2A", relief="sunken", borderwidth=2, highlightbackground="#8B0000")
result_text_frame.pack(padx=30, pady=10, fill="both", expand=True)

result_text = tk.Text(result_text_frame, font=("Consolas", 12), wrap="word", height=15, bg="#2A2A2A", fg="#FFFFFF", 
                      borderwidth=0, highlightthickness=0, insertbackground="#FF4040")
result_text.pack(side="left", fill="both", expand=True)

scrollbar = tk.Scrollbar(result_text_frame, orient="vertical", command=result_text.yview, bg="#3A3A3A", troughcolor="#1A1A1A", 
                         highlightthickness=0, highlightbackground="#8B0000")
scrollbar.pack(side="right", fill="y")
result_text.config(yscrollcommand=scrollbar.set, state="disabled")

result_text.tag_configure("header", font=("Orbitron", 14, "bold"), foreground="#FF4040")
result_text.tag_configure("subheader", font=("Orbitron", 12, "bold"), foreground="#8B0000")
result_text.tag_configure("item", font=("Consolas", 12), foreground="#FFFFFF")

# ======= MAIN PAGE =========
main_frame = tk.Frame(root, bg="#1A1A1A")
pages["main"] = main_frame

label = tk.Label(main_frame, text="Enter Target Domain:", font=("Orbitron", 14, "bold"), bg="#1A1A1A", fg="#FF4040")
label.pack(pady=(30, 10))

entry = ttk.Entry(main_frame, width=40, style='TEntry')
entry.pack(padx=30)

var1 = tk.BooleanVar()
var2 = tk.BooleanVar()
var3 = tk.BooleanVar()

check1 = ttk.Checkbutton(main_frame, text="Passive Scan", variable=var1, style="TCheckbutton")
check1.pack(anchor="w", padx=40, pady=8)

option2_frame = tk.Frame(main_frame, bg="#1A1A1A")
option2_frame.pack(anchor="w", padx=40, pady=8)

check2 = ttk.Checkbutton(option2_frame, text="Active Scan", variable=var2, style="TCheckbutton")
check2.pack(side="left")

sub_option_frame = tk.Frame(option2_frame, bg="#1A1A1A")
sub_option_var = tk.IntVar(value=0)

threads_label = tk.Label(sub_option_frame, text="Threads:", font=("Orbitron", 11), bg="#1A1A1A", fg="#FF4040")
threads_label.pack(side="left", padx=10)
threads_entry = ttk.Entry(sub_option_frame, width=5, style='TEntry')
threads_entry.insert(0, "10")
threads_entry.pack(side="left", padx=10)

def toggle_sub_options():
    if var2.get():
        sub_option_frame.pack(side="left", padx=10)
    else:
        sub_option_frame.pack_forget()
        sub_option_var.set(0)

check2.config(command=toggle_sub_options)

radio1 = ttk.Radiobutton(sub_option_frame, text="Short", variable=sub_option_var, value=1, style="TRadiobutton")
radio1.pack(side="left", padx=10)
radio2 = ttk.Radiobutton(sub_option_frame, text="Full", variable=sub_option_var, value=2, style="TRadiobutton")
radio2.pack(side="left", padx=10)

check3 = ttk.Checkbutton(main_frame, text="WAF Detection", variable=var3, style="TCheckbutton")
check3.pack(anchor="w", padx=40, pady=8)

result_label = tk.Label(main_frame, text="", font=("Orbitron", 12), bg="#1A1A1A", fg="#FF4040", wraplength=600)
result_label.pack(pady=15)

def validate_domain():
    domain = entry.get().strip()
    threads = threads_entry.get().strip()

    if not domain:
        result_label.config(text="Domain field cannot be empty!")
        return

    if not (var1.get() or var2.get() or var3.get()):
        result_label.config(text="Please select at least one scan option!")
        return

    if not re.match(pattern, domain):
        result_label.config(text="Invalid domain format.")
        return

    if var2.get() and sub_option_var.get() == 0:
        result_label.config(text="Please select a mode for Active Scan!")
        return

    if var2.get() and threads and (not threads.isdigit() or int(threads) <= 0):
        result_label.config(text="Threads must be a positive integer!")
        return

    tld = f".{domain.split('.')[-1]}"
    if tld not in common_tlds:
        result_label.config(text=f"Warning: TLD {tld} is uncommon. Please verify it.")
        return

    try:
        passive_output = command1(domain) if var1.get() else ""
        active_output = ""
        active_files = {}
        if var2.get():
            sub_option = "short" if sub_option_var.get() == 1 else "full"
            active_output, active_files = command2(domain, sub_option, threads)
        waf_output = command3(domain) if var3.get() else ""

        result_text.config(state="normal")
        result_text.delete("1.0", "end")

        if passive_output:
            result_text.insert("end", "Passive Scan Results\n", "header")
            result_text.insert("end", "-----------------\n")
            result_text.insert("end", f"{passive_output}\n\n", "item")

        if active_output:
            result_text.insert("end", "Active Scan Results\n", "header")
            result_text.insert("end", "-----------------\n")
            result_text.insert("end", f"{active_output}\n\n", "item")

            if active_files:
                result_text.insert("end", "Active Scan Output Files\n", "header")
                result_text.insert("end", "-----------------------\n")
                file_descriptions = {
                    "open_ports.txt": "Open Ports: List of open ports detected by Nmap",
                    "services.txt": "Services: Details of services running on open ports",
                    "os.txt": "OS Details: Operating system information (if detected)",
                    "domains.txt": "Subdomains: Discovered subdomains",
                    "ips.txt": "IP Addresses: IPs associated with subdomains"
                }
                for file_name, content in active_files.items():
                    result_text.insert("end", f"{file_descriptions.get(file_name, file_name)}\n", "subheader")
                    if content.startswith("[Empty]") or content.startswith("[Not Found]") or content.startswith("[Error]"):
                        result_text.insert("end", f"{content}\n\n", "item")
                    else:
                        lines = content.splitlines()
                        for line in lines:
                            result_text.insert("end", f"  • {line}\n", "item")
                        result_text.insert("end", "\n")

        if waf_output:
            result_text.insert("end", "WAF Detection Results\n", "header")
            result_text.insert("end", "-------------------\n")
            result_text.insert("end", f"{waf_output}\n\n", "item")

        if not (passive_output or active_output or waf_output):
            result_text.insert("end", "No output to display.\n", "item")

        result_text.config(state="disabled")
        result_label.config(text="Scan completed successfully!", fg="#00FF00")
        show_page("result")

    except Exception as e:
        result_label.config(text=f"Error: {str(e)}", fg="#FF4040")

validate_button = ttk.Button(main_frame, text="Initiate Scan", command=validate_domain, style="TButton")
validate_button.pack(pady=20)

# ======= EXPLOIT PAGE =========
exploit_frame = tk.Frame(root, bg="#1A1A1A")
pages["exploit"] = exploit_frame

exploit_title = tk.Label(exploit_frame, text="Exploit Target", font=("Orbitron", 18, "bold"), bg="#1A1A1A", fg="#FF4040",
                         highlightthickness=2, highlightbackground="#8B0000")
exploit_title.pack(pady=20)

# Input fields frame
input_frame = tk.Frame(exploit_frame, bg="#1A1A1A")
input_frame.pack(pady=20)

# URL entry
url_label = tk.Label(input_frame, text="Target URL:", font=("Orbitron", 12, "bold"), bg="#1A1A1A", fg="#FF4040")
url_label.pack(anchor="w", padx=40)
url_entry = ttk.Entry(input_frame, width=40, style='TEntry')
url_entry.pack(padx=40, pady=8)

# Cookie section
cookie_var = tk.BooleanVar()
cookie_check = ttk.Checkbutton(input_frame, text="Inject Cookie", variable=cookie_var, style="TCheckbutton")
cookie_check.pack(anchor="w", padx=40, pady=8)

cookie_frame = tk.Frame(input_frame, bg="#1A1A1A")
cookie_name_label = tk.Label(cookie_frame, text="Cookie Name:", font=("Orbitron", 11), bg="#1A1A1A", fg="#FF4040")
cookie_name_label.pack(side="left", padx=5)
cookie_name_entry = ttk.Entry(cookie_frame, width=15, style='TEntry')
cookie_name_entry.pack(side="left", padx=5)
cookie_value_label = tk.Label(cookie_frame, text="Cookie Value:", font=("Orbitron", 11), bg="#1A1A1A", fg="#FF4040")
cookie_value_label.pack(side="left", padx=5)
cookie_value_entry = ttk.Entry(cookie_frame, width=15, style='TEntry')
cookie_value_entry.pack(side="left", padx=5)

# Vulnerability selection
vuln_frame = tk.Frame(input_frame, bg="#1A1A1A")
xss_var = tk.BooleanVar()
sqli_var = tk.BooleanVar()

xss_check = ttk.Checkbutton(vuln_frame, text="XSS", variable=xss_var, style="TCheckbutton")
xss_check.pack(anchor="w", padx=40, pady=5)
sqli_check = ttk.Checkbutton(vuln_frame, text="SQLi", variable=sqli_var, style="TCheckbutton")
sqli_check.pack(anchor="w", padx=40, pady=5)

exploit_result_label = tk.Label(exploit_frame, text="", font=("Orbitron", 12), bg="#1A1A1A", fg="#FF4040", wraplength=600)
exploit_result_label.pack(pady=15)

def update_input_fields():
    vuln_frame.pack(pady=10)
    if cookie_var.get():
        cookie_frame.pack(pady=10)
    else:
        cookie_frame.pack_forget()

cookie_check.config(command=update_input_fields)

def scan_target():
    url = url_entry.get().strip()
    cookie_name = cookie_name_entry.get().strip() if cookie_var.get() else ""
    cookie_value = cookie_value_entry.get().strip() if cookie_var.get() else ""

    if not url:
        exploit_result_label.config(text="URL field cannot be empty!", fg="#FF4040")
        return

    # Ensure URL has a protocol
    if not url.startswith(('http://', 'https://')):
        exploit_result_label.config(text="URL must include http:// or https:// protocol!", fg="#FF4040")
        return

    # Extract host part (supporting domains, IPs, and ports)
    try:
        host_part = url.split('//', 1)[1].split('/', 1)[0]
        # Check if host_part is a domain or IP (with optional port)
        if not (re.match(pattern, host_part.split(':')[0]) or re.match(ip_pattern, host_part)):
            exploit_result_label.config(text="Invalid domain or IP format in URL.", fg="#FF4040")
            return
    except IndexError:
        exploit_result_label.config(text="Invalid URL format.", fg="#FF4040")
        return

    if not (xss_var.get() or sqli_var.get()):
        exploit_result_label.config(text="At least one vulnerability must be selected!", fg="#FF4040")
        return

    if cookie_var.get() and (not cookie_name or not cookie_value):
        exploit_result_label.config(text="Both cookie name and value must be provided!", fg="#FF4040")
        return

    # Only check TLD for domains, skip for IPs and continue with warning if needed
    host_without_port = host_part.split(':')[0]
    if re.match(pattern, host_without_port):  # If it's a domain
        tld = f".{host_without_port.split('.')[-1]}"
        if tld not in common_tlds:
            exploit_result_label.config(text=f"Warning: TLD {tld} is uncommon. Please verify it.", fg="#FF4040")
            # Allow continuation despite the warning
    elif not re.match(ip_pattern, host_without_port):
        exploit_result_label.config(text="Invalid IP address format.", fg="#FF4040")
        return

    try:
        # Save to web/xss/data.txt
        xss_dir = os.path.abspath("web/xss")
        os.makedirs(xss_dir, exist_ok=True)
        data_file = os.path.join(xss_dir, "data.txt")
        try:
            with open(data_file, "w") as f:
                f.write(url + "\n")
                f.write(f"{cookie_name}={cookie_value}" if cookie_var.get() else "non" + "\n")
            time.sleep(0.1)  # Small delay to ensure file is written
        except PermissionError:
            exploit_result_label.config(text="Error: No permission to write to web/xss directory.", fg="#FF4040")
            return
        except Exception as e:
            exploit_result_label.config(text=f"Error writing to {data_file}: {str(e)}", fg="#FF4040")
            return

        # Initialize outputs
        code_output = "[Info] No output from code.py (writes to a.txt)"
        method = "None"
        script_output = ""
        sqli_output = ""

        # Run XSS scripts if selected
        if xss_var.get():
            # Run web/xss/code.py
            code_script = os.path.join(xss_dir, "code.py")
            try:
                code_result = subprocess.run(
                    ["python3", code_script],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=xss_dir
                )
                if code_result.stderr:
                    code_output = f"[Warning] code.py stderr:\n{code_result.stderr}"
            except subprocess.CalledProcessError as e:
                code_output = f"[Error] code.py failed:\nExit Code: {e.returncode}\nStderr: {e.stderr or 'No stderr output'}\nStdout: {e.stdout or 'No stdout output'}"
            except FileNotFoundError:
                exploit_result_label.config(text=f"Error: {code_script} not found.", fg="#FF4040")
                return
            except Exception as e:
                code_output = f"[Error] Unexpected error in code.py:\n{str(e)}"

            # Wait for a.txt to be created with retries
            a_file = os.path.join(xss_dir, "a.txt")
            max_attempts = 10
            attempt = 0
            while attempt < max_attempts:
                if os.path.isfile(a_file):
                    try:
                        with open(a_file, "r") as f:
                            first_line = f.readline().strip()
                            if first_line in ["GET", "POST"]:
                                method = first_line
                                break
                            else:
                                method = f"[Warning] Invalid method in a.txt: {first_line}"
                                break
                    except Exception as e:
                        method = f"[Warning] Failed to read a.txt: {str(e)}"
                        break
                time.sleep(0.3)
                attempt += 1

            if method == "None" and attempt == max_attempts:
                method = "[Info] a.txt not found or not created in time."

            # Run appropriate XSS script based on method
            if method == "GET":
                script_path = os.path.join(xss_dir, "get.py")
                try:
                    script_result = subprocess.run(
                        ["python3", script_path],
                        capture_output=True,
                        text=True,
                        check=True,
                        cwd=xss_dir
                    )
                    script_output = script_result.stdout or "[Info] No output from get.py."
                except subprocess.CalledProcessError as e:
                    script_output = f"[Error] get.py failed:\nExit Code: {e.returncode}\nStderr: {e.stderr or 'No stderr output'}\nStdout: {e.stdout or 'No stdout output'}"
                except FileNotFoundError:
                    script_output = "[Info] get.py not found, proceeding."
                except Exception as e:
                    script_output = f"[Error] Unexpected error in get.py:\n{str(e)}"
            elif method == "POST":
                script_path = os.path.join(xss_dir, "post.py")
                try:
                    script_result = subprocess.run(
                        ["python3", script_path],
                        capture_output=True,
                        text=True,
                        check=True,
                        cwd=xss_dir
                    )
                    script_output = script_result.stdout or "[Info] No output from post.py."
                except subprocess.CalledProcessError as e:
                    script_output = f"[Error] post.py failed:\nExit Code: {e.returncode}\nStderr: {e.stderr or 'No stderr output'}\nStdout: {e.stdout or 'No stdout output'}"
                except FileNotFoundError:
                    script_output = "[Info] post.py not found, proceeding."
                except Exception as e:
                    script_output = f"[Error] Unexpected error in post.py:\n{str(e)}"
            else:
                script_output = method  # Display warning/info about a.txt

        # Run SQLi scan if selected
        if sqli_var.get():
            sql_dir = os.path.abspath("web/sql")
            edit_script = os.path.join(sql_dir, "edit.py")
            if not os.path.isfile(edit_script):
                exploit_result_label.config(text=f"Error: {edit_script} not found.", fg="#FF4040")
                return

            # Prepare arguments for edit.py
            args = ["python3", edit_script, "-u", url]
            if cookie_var.get():
                args.extend(["--cookie", f"{cookie_name}={cookie_value}"])
            if method == "POST":
                # For POST, we need to provide --data. Assuming a single parameter for simplicity
                query = urllib.parse.urlparse(url).query
                params = urllib.parse.parse_qs(query) if query else {}
                if params:
                    # Use the first parameter as an example
                    first_param = list(params.keys())[0]
                    data = f"{first_param}={urllib.parse.quote(params[first_param][0])}"
                    args.extend(["--data", data, "--pra", "1"])
                else:
                    # Default data if no query parameters
                    args.extend(["--data", "param=value", "--pra", "1"])
            else:
                # For GET, use --det=0 to test the first parameter
                args.extend(["--det", "0"])

            try:
                print(f"[DEBUG] Running SQLi command: {shlex.join(args)}", file=sys.stderr)
                sqli_result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=sql_dir
                )
                sqli_output = sqli_result.stdout or "[Info] No direct output from edit.py."
                # Read result.txt for SQLi results
                result_file = os.path.join(sql_dir, "result.txt")
                if os.path.isfile(result_file):
                    try:
                        with open(result_file, "r") as f:
                            sqli_output += "\n" + f.read().strip()
                    except Exception as e:
                        sqli_output += f"\n[Warning] Failed to read result.txt: {str(e)}"
                else:
                    sqli_output += "\n[Info] result.txt not found."
            except subprocess.CalledProcessError as e:
                sqli_output = (
                    f"[Error] edit.py failed:\n"
                    f"Exit Code: {e.returncode}\n"
                    f"Stderr: {e.stderr or 'No stderr output'}\n"
                    f"Stdout: {e.stdout or 'No stdout output'}"
                )
            except FileNotFoundError:
                sqli_output = f"[Error] {edit_script} not found."
            except Exception as e:
                sqli_output = f"[Error] Unexpected error in edit.py:\n{str(e)}"

        # Display results
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("end", "Manual Scan Results\n", "header")
        result_text.insert("end", "-----------------\n")
        result_text.insert("end", f"URL: {url}\n", "item")
        if cookie_var.get():
            result_text.insert("end", f"Cookie: {cookie_name}={cookie_value}\n", "item")
        selected_vulns = []
        if xss_var.get():
            selected_vulns.append("XSS")
        if sqli_var.get():
            selected_vulns.append("SQLi")
        result_text.insert("end", f"Vulnerabilities: {', '.join(selected_vulns)}\n", "item")

        if xss_var.get():
            result_text.insert("end", f"XSS code.py Output:\n", "subheader")
            result_text.insert("end", f"{code_output}\n\n", "item")
            result_text.insert("end", f"Method Detected: {method if method in ['GET', 'POST'] else 'None'}\n", "subheader")
            result_text.insert("end", f"XSS Script Output:\n", "subheader")
            result_text.insert("end", f"{script_output}\n\n", "item")

        if sqli_var.get():
            result_text.insert("end", f"SQLi Scan Output:\n", "subheader")
            result_text.insert("end", f"{sqli_output}\n", "item")

        result_text.config(state="disabled")
        exploit_result_label.config(text="Exploit initiated successfully!", fg="#00FF00")
        show_page("result")

    except Exception as e:
        exploit_result_label.config(text=f"Error: {str(e)}", fg="#FF4040")

scan_button = ttk.Button(exploit_frame, text="Launch Exploit", command=scan_target, style="TButton")
scan_button.pack(pady=20)

# ======= START =========
show_page("main")
update_input_fields()
root.mainloop()
