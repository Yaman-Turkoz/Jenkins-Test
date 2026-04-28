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

print("[init] Setting up database...", file=sys.stderr)
try:
    opener.open(f"{BASE}/setup.php",
        urllib.parse.urlencode({"create_db": "Create / Reset Database"}).encode())
    time.sleep(5)
except Exception as e:
    print(f"[init] DB setup error (continuing): {e}", file=sys.stderr)

# DB setup sonrası fresh opener — eski cookie'leri temizle
opener, jar = make_opener()

print("[init] Logging in...", file=sys.stderr)
r = opener.open(f"{BASE}/login.php")
token = get_token(r.read().decode())
print(f"[init] CSRF token retrieved: {token[:10]}...", file=sys.stderr)

opener.open(f"{BASE}/login.php",
    urllib.parse.urlencode({
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": token
    }).encode())

r = opener.open(f"{BASE}/index.php")
if "logout" not in r.read().decode().lower():
    print("[init] ERROR: Login failed!", file=sys.stderr)
    sys.exit(1)
print("[init] Login successful.", file=sys.stderr)

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
