import json
import subprocess
import os
from collections import defaultdict

repo  = os.environ["REPO"]
token = os.environ["GH_TOKEN"]
env   = {**os.environ, "GH_TOKEN": token}

# Read semgrep report
with open("semgrep-report.json") as f:
    semgrep_data = json.load(f)

RULE_TITLES = {
    "reflected-xss":  "XSS Vulnerabilities",
    "ssrf-taint":     "SSRF Vulnerabilities",
    "sql-taint":      "SQL Injection Vulnerabilities",
    "incorrect-sanitization":      "Incorrect Sanitization Vulnerabilities",
    "debug-information-leak":      "Debug/Rrror Information Leak",
}

results = semgrep_data.get("results", [])
created_issues = []  # will be written to created-issues.json for ai_analyze.py

if not results:
    print("Semgrep: No findings — no issues will be opened.")
else:
    groups = defaultdict(list)
    for result in results:
        rule_id = result["check_id"].split(".")[-1]
        groups[rule_id].append(result)

    for rule_id, findings in groups.items():
        human_title = RULE_TITLES.get(rule_id, rule_id)
        title = f"[Semgrep] {human_title}"

        # Build findings markdown and collect structured finding data
        findings_md = ""
        structured_findings = []

        for f in findings:
            try:
                with open(f["path"]) as src:
                    file_lines = src.readlines()
                    matched_code = file_lines[f["start"]["line"] - 1].strip()
            except Exception:
                matched_code = "(could not read line)"

            # Skip obvious false positives (e.g. bare PHP closing tag)
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

            structured_findings.append({
                "file":         f["path"],
                "line":         f["start"]["line"],
                "matched_code": matched_code,
                "rule_message": rule_message,
            })

        if not findings_md:
            print(f"All findings for '{rule_id}' were false positives — skipping issue.")
            continue

        message = findings[0]["extra"]["message"]
        body = f"""## Security Finding
**Rule:** `{rule_id}`

### Description
{message}

### Detected Locations ({len(structured_findings)} finding(s))
{findings_md}
---
"""
        # Create issue and capture the URL to extract the issue number
        result_proc = subprocess.run(
            [
                "gh", "issue", "create",
                "--repo",  repo,
                "--title", title,
                "--body",  body,
                "--label", "security",
            ],
            env=env,
            capture_output=True,
            text=True,
        )

        issue_url = result_proc.stdout.strip()
        print(f"Issue created: {issue_url}")

        # Parse issue number from URL  (e.g. .../issues/42)
        try:
            issue_number = int(issue_url.rstrip("/").split("/")[-1])
            created_issues.append({
                "issue_number": issue_number,
                "rule_id":      rule_id,
                "findings":     structured_findings,
            })
        except ValueError:
            print(f"Could not parse issue number from URL: {issue_url}")

# Write structured issue data for ai_analyze.py
with open("created-issues.json", "w") as f:
    json.dump(created_issues, f, indent=2, ensure_ascii=False)

print(f"\n{len(created_issues)} issue(s) written to created-issues.json")
print("All issues have been processed.")
