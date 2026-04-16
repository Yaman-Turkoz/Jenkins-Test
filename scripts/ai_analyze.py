

import base64
import json
import os
import sys
import urllib.request
import urllib.error


GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GH_TOKEN     = os.environ.get("GH_TOKEN", "")
REPO         = os.environ.get("REPO", "")         

GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GITHUB_API = "https://api.github.com"

CREATED_ISSUES_FILE = "created-issues.json"


# GitHub API helpers
def _gh_headers():
    return {
        "Authorization":        f"Bearer {GH_TOKEN}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "ai-analyze-script/1.0",
    }


def gh_get(path: str) -> dict:
    url = f"{GITHUB_API}{path}"
    req = urllib.request.Request(url, headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def gh_post_comment(issue_number: int, body: str) -> dict:
    url     = f"{GITHUB_API}/repos/{REPO}/issues/{issue_number}/comments"
    payload = json.dumps({"body": body}).encode("utf-8")
    req     = urllib.request.Request(
        url,
        data=payload,
        headers={**_gh_headers(), "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def fetch_file_content(file_path: str) -> str:
    """Fetch a file from the repo via the GitHub Contents API (base64-decoded)."""
    try:
        data    = gh_get(f"/repos/{REPO}/contents/{file_path}")
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return content
    except Exception as exc:
        return f"(could not fetch file: {exc})"


# Groq API helper
def call_groq(prompt: str) -> str:
    payload = {
        "model":       "llama-3.3-70b-versatile",
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens":  2048,
    }
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        GROQ_URL,
        data=body,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "User-Agent":    "python-urllib/3.11",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = json.loads(resp.read().decode())
    return raw["choices"][0]["message"]["content"]


# Prompt builder

def build_analysis_prompt(rule_id: str, findings_with_code: list) -> str:
    findings_block = ""
    for idx, f in enumerate(findings_with_code, start=1):
        # Limit full-file context to avoid token overflow
        file_ctx = f["file_content"][:8000]
        if len(f["file_content"]) > 8000:
            file_ctx += "\n... (file truncated for brevity)"

        findings_block += f"""
### Finding {idx}
- **File:** `{f['file']}`
- **Line:** {f['line']}
- **Semgrep Message:** {f['rule_message']}

**Matched line:**
```php
{f['matched_code']}
```

**Full file context (read-only, for taint analysis):**
```php
{file_ctx}
```
"""

    return f"""You are a Semgrep triage engine.
Your job is NOT to perform a security review.
Your ONLY task is to validate whether the reported Semgrep finding matches the exact taint flow shown in code.

Semgrep triggered rule `{rule_id}` on the following finding(s) in a PHP codebase.

{findings_block}

---

IMPORTANT SCOPE RULES:
Your analysis scope is STRICTLY LIMITED to the vulnerability type indicated by rule `{rule_id}`. 
You CAN'T mention any other findings that are not listed inside this specific issue.

SANITIZATION RULES:

- Not all filtering functions are considered safe.
- Weak or partial sanitization (e.g., regex-based filtering, blacklist approaches like preg_replace removing <script> tags) MUST be treated as INSUFFICIENT.
- Such cases MUST be classified as TRUE POSITIVE.

- Only strong, context-aware output encoding functions (e.g., htmlspecialchars in PHP for HTML context) are considered valid protection.

- If user-controlled data reaches HTML output and is not protected by a proper encoding function like htmlspecialchars, it MUST be considered a TRUE POSITIVE, even if some filtering exists.

DO NOT:
- Mention unrelated vulnerabilities.
- Suggest fixes for other security issues found in the code.
- Provide proof-of-concept for other vulnerabilities.
- Mention "however there may be another issue..." or similar language.
- Expand analysis beyond the reported finding.

If the finding is FALSE POSITIVE:
- Explain ONLY why this finding is false positive.
- DO NOT provide Fix / PoC / Code Flow.
- DO NOT suggest unrelated remediation.

If the finding is TRUE POSITIVE:
- Provide Fix / PoC / Code Flow ONLY for THIS finding.

---

Analyse every finding carefully and produce the following four sections.
Be specific, precise, and reference actual variable names, function names, and line numbers from the code above.

## Verdict
State clearly: **TRUE POSITIVE** or **FALSE POSITIVE**.
Explain *why* in 2-4 sentences referencing the actual code.
If multiple findings exist, give a verdict for each one (e.g. "Finding 1: TRUE POSITIVE — ..."). Becareful with the formatting, put new-line between findings.

## Fix
*(Skip this section entirely if all findings are FALSE POSITIVE.)*
Provide a concrete fix for each true-positive finding.
Include a before/after code snippet written in PHP.
Write the codes in this part in a single box.

## Proof of Concept
*(Skip this section entirely if all findings are FALSE POSITIVE.)*
Write a realistic, step-by-step PoC showing how an attacker could exploit this vulnerability.
For web vulnerabilities include the exact HTTP request or browser-side payload.

## Code Flow
*(Skip this section entirely if all findings are FALSE POSITIVE.)*
Show taint flow from the user-controlled source to the vulnerable sink,
referencing actual variable names and line numbers.
Only for this part: Wrap ALL code lines in ```php code blocks and preserve them exactly.
Only for this part: Don't put any comments, don't explain the code for.
Write the codes in this part in a single box.
Use a more visual approach using arrows, like a tree from top to bottom.
example:
    Line 3: $name = $_GET['name']
        ↓
    Line 10: $name = htmlspecialchars($name)
        ↓
    Line 13: curl_init($name)

---
Respond **only** with the four Markdown sections above. Do not add any extra commentary outside them.
"""


# Comment formatter

def format_comment(rule_id: str, analysis_text: str) -> str:
    return f"""## 🤖 AI Security Analysis

> **Rule:** `{rule_id}`
> This analysis was generated automatically. Always verify findings manually before acting on them.

---

{analysis_text}

---
*Powered by Groq · llama-3.3-70b-versatile*
"""



def main():
    print(f"GH_TOKEN present     : {'YES' if GH_TOKEN else 'NO'}")
    print(f"GROQ_API_KEY present : {'YES' if GROQ_API_KEY else 'NO'}")
    print(f"REPO                 : {REPO}")

    if not GH_TOKEN:
        print("ERROR: Missing GH_TOKEN")
        sys.exit(1)
    if not GROQ_API_KEY:
        print("ERROR: Missing GROQ_API_KEY")
        sys.exit(1)
    if not REPO:
        print("ERROR: Missing REPO")
        sys.exit(1)

    # Load issues created by create_issues.py
    if not os.path.exists(CREATED_ISSUES_FILE):
        print(f"{CREATED_ISSUES_FILE} not found — nothing to analyse.")
        return

    with open(CREATED_ISSUES_FILE) as f:
        issues = json.load(f)

    if not issues:
        print("No issues to analyse.")
        return

    print(f"\nFound {len(issues)} issue(s) to analyse.\n")

    for issue in issues:
        issue_number = issue["issue_number"]
        rule_id      = issue["rule_id"]
        findings     = issue["findings"]

        print(f"─── Issue #{issue_number}  (rule: {rule_id}) ───")

        # Fetch full file content for each finding via GitHub API
        findings_with_code = []
        for finding in findings:
            file_path    = finding["file"]
            line         = finding["line"]
            matched_code = finding.get("matched_code", "")
            rule_message = finding.get("rule_message", "")

            print(f"  → Fetching {file_path} ...")
            file_content = fetch_file_content(file_path)

            findings_with_code.append({
                "file":         file_path,
                "line":         line,
                "matched_code": matched_code,
                "rule_message": rule_message,
                "file_content": file_content,
            })

        # Build prompt and query the LLM
        prompt = build_analysis_prompt(rule_id, findings_with_code)

        print(f"  → Calling AI ...")
        try:
            analysis_text = call_groq(prompt)
        except Exception as exc:
            print(f"  ✗ AI call failed: {exc}")
            analysis_text = f"AI analysis could not be completed due to an API error:\n```\n{exc}\n```"

        # Post comment on the GitHub issue
        comment_body = format_comment(rule_id, analysis_text)
        print(f"  → Posting comment on issue #{issue_number} ...")
        try:
            gh_post_comment(issue_number, comment_body)
            print(f"  ✓ Comment posted on issue #{issue_number}")
        except Exception as exc:
            print(f"  ✗ Failed to post comment: {exc}")

    print("\nAI analysis complete.")


if __name__ == "__main__":
    main()
