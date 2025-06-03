
# SE7 Network Scanner

SE7 is a network reconnaissance and scanning tool and explotaion developed in Python. It combines multiple scanning techniques to identify active devices, services, domains, and vulnerabilities on a network.

## Features
- DNS list-based scanning
- Brute-force subdomain and IP discovery
- Port and service scanning
- Graphical User Interface (GUI)

## Project Structure

```
se7/
├── lan.py                         
├── se72ch/
│   ├── GUI.py                     # GUI for the scanner
│   ├                     
│   └── home/
│       └── active/
│           └── combined_scan/
│               ├── DNSlist_long.txt
│               ├── DNSlist_short.txt
│               ├── combined_scan.py
│               └── results/
│                   ├── bruteforce/
│                   │   ├── domains.txt
│                   │   └── ips.txt
│                   └── scan/
│                       ├── open_ports.txt
│                       └── services.txt
```

## Requirements

- Python 3.x
- Required libraries (install using pip):

```bash
pip install -r requirements.txt
```

> Note: The `requirements.txt` file is not included. You may need to manually add dependencies used in the scripts.

## Usage

### for launcher 

```bash
python lan.py
```

### GUI

```bash
python se72ch/GUI.py
```
inside it you found 3 page 
home -- used for passive and active and WAF scan  
expolit -- have two option SQL and XSS 
output-- for result 

note: target like this eccouncil.org not like this https://www.eccouncil.org/
in SQL keep target with parmeter in GET method like this "http://testphp.vulnweb.com/artists.php?artist=1"
## License

This project is intended for educational and ethical use only.

---

**Author:** Se27rch Group  
**Last Updated:** June 2025
