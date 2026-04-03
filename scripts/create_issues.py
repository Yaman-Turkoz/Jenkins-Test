import json
import subprocess
import os
from collections import defaultdict

repo  = os.environ["REPO"]
token = os.environ["GH_TOKEN"]
env   = {**os.environ, "GH_TOKEN": token}

# read files
with open("semgrep-report.json") as f:
    semgrep_data = json.load(f)

with open("ai-analysis.json") as f:
    ai = json.load(f)

# only read specific lines
def read_line(path, line_number):
    try:
        with open(path) as f:
            lines = f.readlines()
        return lines[line_number - 1].strip()
    except Exception:
        return "(satır okunamadı)"

# semgrep findings
RULE_TITLES = {
    "xss-and-debug":  "XSS & Debug Vulnerabilities",
    "code-injection": "Code Injection Vulnerabilities",
    "ssrf-taint":     "SSRF Vulnerabilities",
}

results = semgrep_data.get("results", [])

if not results:
    print("Semgrep: No findings, no issues will be opened")
else:
    groups = defaultdict(list)
    for result in results:
        rule_id = result["check_id"].split(".")[-1]
        groups[rule_id].append(result)

    for rule_id, findings in groups.items():
        human_title = RULE_TITLES.get(rule_id, rule_id)
        title = f"[Semgrep] {human_title}"

        findings_md = ""
        for f in findings:
            try:
                with open(f["path"]) as src:
                    file_lines = src.readlines()
                    matched_code = file_lines[f["start"]["line"] - 1].strip()
            except Exception:
                matched_code = "(could not read line)"

            # skip false false positive php closing tag
            if matched_code.strip() in ("?>",):
                print(f"Skipping false positive at {f['path']}:{f['start']['line']}")
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
            print(f"All findings for '{rule_id}' were false positives. Skipping issue.")
            continue

        message = findings[0]["extra"]["message"]
        body = f"""## Security Finding
**Rule:** `{rule_id}`

### Description
{message}

### Detected Locations ({len(findings)} finding(s))
{findings_md}
---
*This issue was automatically created by the GitHub Actions Semgrep scan.*
"""
        subprocess.run([
            "gh", "issue", "create",
            "--repo", repo,
            "--title", title,
            "--body", body,
            "--label", "security"
        ], env=env)
        print(f"Issue has been opened (Semgrep): {title}")

# additional ai findings
additional = [
    f for f in ai.get("additional_findings", [])
    if f.get("severity") in ("HIGH", "MEDIUM")
]

if not additional:
    print("AI: No additional findings.")
else:
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

"""
        subprocess.run([
            "gh", "issue", "create",
            "--repo", repo,
            "--title", title,
            "--body", body,
            "--label", "security"
        ], env=env)
        print(f"Issue has been opened (AI): {title}")

print("\n All issues have been processed.")
