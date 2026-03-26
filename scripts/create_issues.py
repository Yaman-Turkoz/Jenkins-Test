import json, subprocess, os
from collections import defaultdict

with open('semgrep-report.json') as f:
    data = json.load(f)

results = data.get('results', [])
repo  = os.environ['REPO']
token = os.environ['GH_TOKEN']
env   = {**os.environ, "GH_TOKEN": token}

# Close existing [Semgrep] issues
existing = subprocess.run([
    "gh", "issue", "list",
    "--repo", repo,
    "--state", "open",
    "--label", "security",
    "--json", "number,title",
    "--jq", '.[] | select(.title | startswith("[Semgrep]")) | .number'
], capture_output=True, text=True, env=env)

for number in existing.stdout.strip().splitlines():
    subprocess.run([
        "gh", "issue", "close", number,
        "--repo", repo,
        "--comment", "A new Semgrep scan has started. This issue is being refreshed."
    ], env=env)
    print(f"Closed issue #{number}")

if not results:
    print("No findings. No issues will be created.")
    exit(0)

RULE_TITLES = {
    'xss-and-debug':  'XSS & Debug Vulnerabilities',
    'code-injection': 'Code Injection Vulnerabilities',
}

# Group findings by rule_id
groups = defaultdict(list)
for result in results:
    rule_id = result['check_id'].split('.')[-1]
    groups[rule_id].append(result)

for rule_id, findings in groups.items():
    human_title = RULE_TITLES.get(rule_id, rule_id)
    title = f"[Semgrep] {human_title}"

    findings_md = ""
    for f in findings:
        # Read the matched line directly from the file
        try:
            with open(f['path']) as src:
                file_lines = src.readlines()
                matched_code = file_lines[f['start']['line'] - 1].strip()
        except Exception:
            matched_code = "(could not read line)"

        check_id     = f['check_id'].split('.')[-1]
        rule_message = f['extra']['message'].split('.')[0]

        findings_md += (
            f"**`{f['path']}` — line {f['start']['line']}** "
            f"(`{check_id}`)\n"
            f"> {rule_message}\n"
            f"```php\n{matched_code}\n```\n\n"
        )

    message = findings[0]['extra']['message']

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

    print(f"Opened issue: {title} ({len(findings)} finding(s))")
