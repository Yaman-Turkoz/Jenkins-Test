#!/usr/bin/env python3
import urllib.request, urllib.parse, http.cookiejar, re, sys, time

BASE = "http://dvwa"

def make_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar)), jar

def get_token(html):
    m = re.search(r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)", html)
    if not m:
        m = re.search(r"value=['\"]([^'\"]+)['\"].*?name=['\"]user_token['\"]", html)
    return m.group(1) if m else ""

def try_login():
    opener, jar = make_opener()
    try:
        r = opener.open(f"{BASE}/login.php")
        token = get_token(r.read().decode())
        if not token:
            return None, None
        opener.open(f"{BASE}/login.php",
            urllib.parse.urlencode({
                "username": "admin", "password": "password",
                "Login": "Login", "user_token": token
            }).encode())
        r = opener.open(f"{BASE}/index.php")
        if "logout" in r.read().decode().lower():
            return opener, jar
    except Exception as e:
        print(f"[init] Login attempt error: {e}", file=sys.stderr)
    return None, None

opener, jar = make_opener()

print("[init] Waiting for DVWA...", file=sys.stderr)
for _ in range(40):
    try:
        r = opener.open(f"{BASE}/login.php")
        if r.status == 200:
            print("[init] DVWA is ready.", file=sys.stderr)
            break
    except Exception as e:
        print(f"[init] Not ready yet: {e}", file=sys.stderr)
        time.sleep(3)

# DB setup yap
print("[init] Setting up database...", file=sys.stderr)
try:
    setup_opener, _ = make_opener()
    setup_opener.open(f"{BASE}/setup.php",
        urllib.parse.urlencode({"create_db": "Create / Reset Database"}).encode())
except Exception as e:
    print(f"[init] DB setup error (continuing): {e}", file=sys.stderr)

# Login'i retry ile dene — DB setup tamamlanana kadar bekle
print("[init] Waiting for DB setup to complete...", file=sys.stderr)
logged_opener = None
for attempt in range(15):
    time.sleep(5)
    print(f"[init] Login attempt {attempt + 1}/15...", file=sys.stderr)
    logged_opener, jar = try_login()
    if logged_opener:
        print("[init] Login successful.", file=sys.stderr)
        opener = logged_opener
        break
    print(f"[init] Not ready yet, retrying...", file=sys.stderr)

if not logged_opener:
    print("[init] ERROR: Login failed after all attempts!", file=sys.stderr)
    sys.exit(1)

# Security seviyesini low yap
r = opener.open(f"{BASE}/security.php")
token = get_token(r.read().decode())
opener.open(f"{BASE}/security.php",
    urllib.parse.urlencode({
        "security": "low", "seclev_submit": "Submit", "user_token": token
    }).encode())
print("[init] Security level set to low.", file=sys.stderr)

for c in jar:
    if c.name == "PHPSESSID":
        print(c.value)
        sys.exit(0)

print("[init] ERROR: Session cookie not found!", file=sys.stderr)
sys.exit(1)
