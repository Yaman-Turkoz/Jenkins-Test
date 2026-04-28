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

def try_login(opener):
    try:
        r = opener.open(f"{BASE}/login.php")
        token = get_token(r.read().decode())
        if not token:
            return False
        opener.open(f"{BASE}/login.php",
            urllib.parse.urlencode({
                "username": "admin", "password": "password",
                "Login": "Login", "user_token": token
            }).encode())
        r = opener.open(f"{BASE}/index.php")
        return "logout" in r.read().decode().lower()
    except:
        return False

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

# Önce login dene — başarılıysa DB setup'ı atla
print("[init] Trying login without DB setup...", file=sys.stderr)
if try_login(opener):
    print("[init] Login successful (DB already set up).", file=sys.stderr)
else:
    # Login başarısız — DB kurulmamış, setup yap
    print("[init] Login failed, setting up database...", file=sys.stderr)
    opener, jar = make_opener()
    try:
        opener.open(f"{BASE}/setup.php",
            urllib.parse.urlencode({"create_db": "Create / Reset Database"}).encode())
        time.sleep(5)
    except Exception as e:
        print(f"[init] DB setup error (continuing): {e}", file=sys.stderr)

    opener, jar = make_opener()
    print("[init] Logging in after DB setup...", file=sys.stderr)
    if not try_login(opener):
        print("[init] ERROR: Login failed after DB setup!", file=sys.stderr)
        sys.exit(1)
    print("[init] Login successful.", file=sys.stderr)

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
