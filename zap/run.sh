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
  -autorun /tmp/scan.yaml


