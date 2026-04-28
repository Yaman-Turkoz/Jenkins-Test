#!/bin/bash
set -e

echo "[run] Starting DVWA setup..."
SESSION=$(python3 /zap/wrk/init.py)
echo "[run] Session retrieved: ${SESSION:0:10}..."

sed "s/SESSION_PLACEHOLDER/$SESSION/g" \
    /zap/wrk/scan-template.yaml > /tmp/scan.yaml

# XSS-only scan policy
mkdir -p /root/.ZAP/policies
cat > /root/.ZAP/policies/xss-only.policy << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<policy>
  <name>xss-only</name>
  <scanner>
    <level>3</level>
    <strength>2</strength>
  </scanner>
  <plugins>
    <plugin><id>40012</id><enabled>true</enabled><level>3</level><strength>2</strength></plugin>
    <plugin><id>40014</id><enabled>true</enabled><level>3</level><strength>2</strength></plugin>
    <plugin><id>40016</id><enabled>true</enabled><level>3</level><strength>2</strength></plugin>
    <plugin><id>40017</id><enabled>true</enabled><level>3</level><strength>2</strength></plugin>
  </plugins>
</policy>
EOF

echo "[run] Starting ZAP scan..."
zap.sh -cmd \
  -config "replacer.full_list(0).description=DVWACookie" \
  -config "replacer.full_list(0).enabled=true" \
  -config "replacer.full_list(0).matchtype=REQ_HEADER" \
  -config "replacer.full_list(0).matchstr=Cookie" \
  -config "replacer.full_list(0).matchregex=false" \
  -config "replacer.full_list(0).replacement=PHPSESSID=${SESSION}; security=low" \
  -autorun /tmp/scan.yaml
