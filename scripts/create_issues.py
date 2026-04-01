import json
import subprocess
import os
from collections import defaultdict

# ── Ortam değişkenleri ────────────────────────────────────────────────────────
repo  = os.environ["REPO"]
token = os.environ["GH_TOKEN"]
env   = {**os.environ, "GH_TOKEN": token}

# ── Dosyaları oku ─────────────────────────────────────────────────────────────
with open("semgrep-report.json") as f:
    semgrep_data = json.load(f)

with open("ai-analysis.json") as f:
    ai = json.load(f)

# ── AI kararını kontrol et ────────────────────────────────────────────────────
print(f"\n🤖 AI Kararı: {'Issue AÇILACAK ✅' if ai['open_issue'] else 'Issue AÇILMAYACAK 🚫'}")
print(f"   Özet: {ai.get('summary', '')}\n")

if not ai.get("open_issue", False):
    print("AI issue açılmasına gerek olmadığına karar verdi. Çıkılıyor.")
    exit(0)

# ── Yardımcı: dosyadan belirli satırı oku ────────────────────────────────────
def read_line(path, line_number):
    try:
        with open(path) as f:
            lines = f.readlines()
        return lines[line_number - 1].strip()
    except Exception:
        return "(satır okunamadı)"

# ═══════════════════════════════════════════════════════════════════════════════
# ISSUE 1: Semgrep bulguları (AI tarafından onaylananlar)
# ═══════════════════════════════════════════════════════════════════════════════
RULE_TITLES = {
    "xss-and-debug":  "XSS & Debug Vulnerabilities",
    "code-injection": "Code Injection Vulnerabilities",
    "ssrf-taint":     "SSRF Vulnerabilities",
}

# AI'ın onayladığı semgrep bulgularını bul
confirmed_ids = {
    f["rule_id"]
    for f in ai.get("semgrep_findings", [])
    if f.get("confirmed")
}

# Semgrep raporundaki orijinal bulguları rule_id'ye göre grupla
semgrep_results = semgrep_data.get("results", [])
groups = defaultdict(list)
for result in semgrep_results:
    rule_id = result["check_id"].split(".")[-1]
    if rule_id in confirmed_ids:
        groups[rule_id].append(result)

# AI'ın onay/red gerekçelerini al (rule_id → reason)
ai_reasons = {
    f["rule_id"]: f.get("reason", "")
    for f in ai.get("semgrep_findings", [])
}

for rule_id, findings in groups.items():
    human_title = RULE_TITLES.get(rule_id, rule_id)
    title = f"[Semgrep] {human_title}"

    findings_md = ""
    for f in findings:
        matched_code = read_line(f["path"], f["start"]["line"])

        # PHP kapanış tag'i false positive'i atla
        if matched_code.strip() in ("?>",):
            continue

        check_id     = f["check_id"].split(".")[-1]
        rule_message = f["extra"]["message"].split(".")[0]
        findings_md += (
            f"**`{f['path']}` — line {f['start']['line']}** "
            f"(`{check_id}`)\n"
            f"> {rule_message}\n"
            f"```php\n{matched_code}\n```\n\n"
        )

    if not findings_md:
        continue

    ai_reason = ai_reasons.get(rule_id, "")
    body = f"""## Security Finding — Semgrep + AI Confirmed

**Rule:** `{rule_id}`

### Description
{findings[0]['extra']['message']}

### Detected Locations ({len(findings)} finding(s))
{findings_md}

### 🤖 AI Değerlendirmesi
{ai_reason}

---
*Bu issue Semgrep tarafından tespit edildi ve AI tarafından doğrulandı.*
"""
    subprocess.run([
        "gh", "issue", "create",
        "--repo", repo,
        "--title", title,
        "--body", body,
        "--label", "security"
    ], env=env)
    print(f"✅ Issue açıldı (Semgrep): {title}")

# ═══════════════════════════════════════════════════════════════════════════════
# ISSUE 2: AI'ın kendi bulduğu ek açıklar
# ═══════════════════════════════════════════════════════════════════════════════
additional = [
    f for f in ai.get("additional_findings", [])
    if f.get("severity") in ("HIGH", "MEDIUM")
]

for finding in additional:
    title = f"[AI] {finding['title']}"
    matched_code = read_line(finding["file"], finding.get("line", 1))

    body = f"""## Security Finding — AI Detected

**Severity:** `{finding['severity']}`
**File:** `{finding['file']}` — line {finding.get('line', '?')}

### Description
{finding['description']}

### Detected Code
```php
{matched_code}
```

---
*Bu issue yalnızca AI analizi tarafından tespit edildi (Semgrep tarafından yakalanmadı).*
"""
    subprocess.run([
        "gh", "issue", "create",
        "--repo", repo,
        "--title", title,
        "--body", body,
        "--label", "security"
    ], env=env)
    print(f"✅ Issue açıldı (AI): {title}")

print("\n🏁 Tüm issue'lar işlendi.")
