#!/bin/bash
set -e

echo "[run] Starting DVWA setup..."
SESSION=$(python3 /zap/wrk/init.py)
echo "[run] Session retrieved: ${SESSION:0:10}..."

sed "s/SESSION_PLACEHOLDER/$SESSION/g" \
    /zap/wrk/scan-template.yaml > /tmp/scan.yaml

echo "[run] Starting ZAP scan..."
zap.sh -cmd \
  -config "replacer.full_list(0).description=DVWACookie" \
  -config "replacer.full_list(0).enabled=true" \
  -config "replacer.full_list(0).matchtype=REQ_HEADER" \
  -config "replacer.full_list(0).matchstr=Cookie" \
  -config "replacer.full_list(0).matchregex=false" \
  -config "replacer.full_list(0).replacement=PHPSESSID=${SESSION}; security=low" \
  -config "scanner.policy=xss-only" \
  -config "policies.policy(0).name=xss-only" \
  -config "policies.policy(0).scanner(0).id=40012" \
  -config "policies.policy(0).scanner(0).enabled=true" \
  -config "policies.policy(0).scanner(1).id=40014" \
  -config "policies.policy(0).scanner(1).enabled=true" \
  -config "policies.policy(0).scanner(2).id=40016" \
  -config "policies.policy(0).scanner(2).enabled=true" \
  -config "policies.policy(0).scanner(3).id=40017" \
  -config "policies.policy(0).scanner(3).enabled=true" \
  -autorun /tmp/scan.yaml
