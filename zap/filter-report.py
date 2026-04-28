#!/usr/bin/env python3
import re, sys

XSS_KEYWORDS = [
    "cross site scripting",
    "xss",
]

def keep_alert(block):
    lower = block.lower()
    return any(kw in lower for kw in XSS_KEYWORDS)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    content = f.read()

# Alert bloklarını ayır ve sadece XSS olanları tut
parts = re.split(r'(<div class="alert-detail)', content)

header = parts[0]
alert_blocks = []
for i in range(1, len(parts), 2):
    block = parts[i] + (parts[i+1] if i+1 < len(parts) else "")
    if keep_alert(block):
        alert_blocks.append(block)

filtered = header + "".join(alert_blocks)

with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(filtered)

print(f"[filter] Kept {len(alert_blocks)} XSS-related alert block(s).")
