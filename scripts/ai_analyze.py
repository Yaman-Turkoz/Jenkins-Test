

import base64
import json
import os
import sys
import urllib.request
import urllib.error



GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GH_TOKEN     = os.environ.get("GH_TOKEN", "")
REPO         = os.environ.get("REPO", "")          # e.g. "owner/repo-name"

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

    return f"""You are an expert application security engineer performing a thorough code review.

Semgrep triggered rule `{rule_id}` on the following finding(s) in a PHP codebase.

{findings_block}

---

════════════════════════════════════════
STRICT RULES — YOU MUST FOLLOW EXACTLY
════════════════════════════════════════

RULE 1 — SCOPE LOCK:
  You are analysing ONLY the finding(s) listed above.
  You MUST NOT mention, reference, or hint at any other vulnerability,
  issue, rule, or file that is not part of the finding(s) above.
  Even if you notice another bug in the code, DO NOT mention it.

RULE 2 — FALSE POSITIVE HARD STOP:
  If your verdict for a finding is FALSE POSITIVE:
    - Write ONLY the ## Verdict section.
    - DO NOT write ## Fix, ## Proof of Concept, or ## Code Flow.
    - DO NOT suggest any fix, workaround, or alternative remediation.
    - DO NOT describe any other vulnerability you noticed in the file.
    - STOP your response after the ## Verdict section.

RULE 3 — TRUE POSITIVE ONLY SECTIONS:
  Write ## Fix, ## Proof of Concept, and ## Code Flow ONLY when the verdict
  is TRUE POSITIVE, and ONLY for the specific vulnerability flagged by
  rule `{rule_id}`.

════════════════════════════════════════

Analyse every finding and produce the sections below.
Be specific and reference actual variable names and line numbers from the code above.

## Verdict
State clearly: **TRUE POSITIVE** or **FALSE POSITIVE**.
Explain *why* in 2-4 sentences referencing the actual code.
If multiple findings exist, give a verdict for each one (e.g. "Finding 1: TRUE POSITIVE — ...").
If ALL findings are FALSE POSITIVE → stop here. Do not write anything else.

## Fix
*(TRUE POSITIVE only — omit this section entirely otherwise.)*
Provide a concrete fix for the flagged vulnerability.
Include a before/after PHP code snippet.

## Proof of Concept
*(TRUE POSITIVE only — omit this section entirely otherwise.)*
Write a realistic, step-by-step PoC showing how an attacker could exploit
the specific vulnerability flagged by rule `{rule_id}`.
For web vulnerabilities include the exact HTTP request or browser-side payload.

## Code Flow
*(TRUE POSITIVE only — omit this section entirely otherwise.)*
Describe the taint flow from the user-controlled source to the vulnerable sink,
referencing actual variable names and line numbers.
Use a numbered list (1 → 2 → 3) to show each hop.

---
Output ONLY the Markdown sections described above.
Do not add preambles, conclusions, disclaimers, or commentary of any kind.
"""


# Comment formatter

def format_comment(rule_id: str, analysis_text: str) -> str:
    return f"""## 🤖 AI Security Analysis

> **Rule:** `{rule_id}`
> This analysis was generated automatically. Always verify findings manually before acting on them.

---

{analysis_text}

---

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
