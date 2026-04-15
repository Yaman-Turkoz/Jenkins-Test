import base64
import json
import os
import re
import sys
import urllib.request
import urllib.error


GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GH_TOKEN     = os.environ.get("GH_TOKEN", "")
REPO         = os.environ.get("REPO", "")

GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GITHUB_API = "https://api.github.com"

CREATED_ISSUES_FILE = "created-issues.json"



def _gh_headers() -> dict:
    return {
        "Authorization":        f"Bearer {GH_TOKEN}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "ai-fix-script/1.0",
    }


def gh_get(path: str) -> dict:
    url = f"{GITHUB_API}{path}"
    req = urllib.request.Request(url, headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def gh_post(path: str, payload: dict) -> dict:
    url  = f"{GITHUB_API}{path}"
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=body,
        headers={**_gh_headers(), "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def gh_put(path: str, payload: dict) -> dict:
    url  = f"{GITHUB_API}{path}"
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=body,
        headers={**_gh_headers(), "Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def fetch_file_with_sha(file_path: str) -> tuple[str, str]:
    """Returns (decoded_content, blob_sha)."""
    data    = gh_get(f"/repos/{REPO}/contents/{file_path}")
    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return content, data["sha"]


def get_default_branch() -> str:
    return gh_get(f"/repos/{REPO}").get("default_branch", "main")


def get_branch_sha(branch: str) -> str:
    return gh_get(f"/repos/{REPO}/git/ref/heads/{branch}")["object"]["sha"]


def create_branch(branch_name: str, from_sha: str) -> None:
    gh_post(f"/repos/{REPO}/git/refs", {
        "ref": f"refs/heads/{branch_name}",
        "sha": from_sha,
    })


def commit_file(file_path: str, new_content: str, blob_sha: str,
                branch: str, message: str) -> None:
    gh_put(f"/repos/{REPO}/contents/{file_path}", {
        "message": message,
        "content": base64.b64encode(new_content.encode("utf-8")).decode("ascii"),
        "sha":     blob_sha,
        "branch":  branch,
    })


def open_pr(title: str, body: str, head: str, base: str) -> dict:
    return gh_post(f"/repos/{REPO}/pulls", {
        "title": title,
        "body":  body,
        "head":  head,
        "base":  base,
    })


def post_issue_comment(issue_number: int, body: str) -> None:
    gh_post(f"/repos/{REPO}/issues/{issue_number}/comments", {"body": body})


# groq helper

def call_groq(prompt: str, max_tokens: int = 4096) -> str:
    payload = {
        "model":       "llama-3.3-70b-versatile",
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens":  max_tokens,
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
    with urllib.request.urlopen(req, timeout=90) as resp:
        raw = json.loads(resp.read().decode())
    return raw["choices"][0]["message"]["content"]


# prompt, response parse

def build_fix_prompt(rule_id: str, findings_with_code: list) -> str:
    findings_block = ""
    for idx, f in enumerate(findings_with_code, start=1):
        file_ctx = f["file_content"][:8000]
        if len(f["file_content"]) > 8000:
            file_ctx += "\n... (file truncated)"
        findings_block += f"""
### Finding {idx}
- **File:** `{f['file']}`
- **Line:** {f['line']}
- **Semgrep message:** {f['rule_message']}
- **Matched line:** `{f['matched_code']}`

**Full file content:**
```php
{file_ctx}
```
"""

    return f"""You are a security code fixer. Semgrep triggered rule `{rule_id}`.

{findings_block}

---
TASK
1. Decide whether each finding is a TRUE POSITIVE or FALSE POSITIVE.
2. If ALL findings are FALSE POSITIVE → respond with exactly one line:
   VERDICT: FALSE_POSITIVE
3. If ANY finding is a TRUE POSITIVE → respond in this EXACT format and nothing else:

VERDICT: TRUE_POSITIVE

FILE: <relative/path/to/file.php>
```php
<complete fixed file content — every single line, not just the changed part>
```

If multiple files need fixing, repeat the FILE block for each one.

RULES
- Return the COMPLETE file, not a diff or snippet.
- Fix ONLY the vulnerability identified by rule `{rule_id}`. Do not change anything else.
- Do not add any explanation, comments, or text outside the format above.
"""


def parse_fix_response(response: str) -> dict:
    """
    Returns one of:
      {"verdict": "FALSE_POSITIVE"}
      {"verdict": "TRUE_POSITIVE", "files": {"path/to/file.php": "fixed content"}}
      {"verdict": "UNKNOWN"}   ← AI response was unparseable
    """
    text = response.strip()

    if re.search(r"VERDICT\s*:\s*FALSE_POSITIVE", text, re.IGNORECASE):
        return {"verdict": "FALSE_POSITIVE"}

    files: dict[str, str] = {}
    # Match every  FILE: <path>\n```php\n<content>\n```  block
    for m in re.finditer(
        r"FILE:\s*(.+?)\n```(?:php)?\n(.*?)```",
        text,
        re.DOTALL,
    ):
        file_path = m.group(1).strip()
        content   = m.group(2)          # keep trailing newline as-is
        files[file_path] = content

    if files:
        return {"verdict": "TRUE_POSITIVE", "files": files}

    return {"verdict": "UNKNOWN"}



def main() -> None:
    print(f"GH_TOKEN present     : {'YES' if GH_TOKEN else 'NO'}")
    print(f"GROQ_API_KEY present : {'YES' if GROQ_API_KEY else 'NO'}")
    print(f"REPO                 : {REPO}")

    if not GH_TOKEN:
        print("ERROR: Missing GH_TOKEN");  sys.exit(1)
    if not GROQ_API_KEY:
        print("ERROR: Missing GROQ_API_KEY"); sys.exit(1)
    if not REPO:
        print("ERROR: Missing REPO"); sys.exit(1)

    if not os.path.exists(CREATED_ISSUES_FILE):
        print(f"{CREATED_ISSUES_FILE} not found — nothing to fix.")
        return

    with open(CREATED_ISSUES_FILE) as f:
        issues = json.load(f)

    if not issues:
        print("No issues to fix.")
        return

    default_branch = get_default_branch()
    print(f"Default branch: {default_branch}\n")

    for issue in issues:
        issue_number = issue["issue_number"]
        rule_id      = issue["rule_id"]
        findings     = issue["findings"]

        print(f"─── Issue #{issue_number}  (rule: {rule_id}) ───")

        # 1. Fetch current file content + blob SHA (needed to commit)
        findings_with_code: list[dict] = []
        file_shas: dict[str, str]      = {}

        for finding in findings:
            file_path = finding["file"]
            print(f"  → Fetching {file_path} ...")
            try:
                content, sha         = fetch_file_with_sha(file_path)
                file_shas[file_path] = sha
            except Exception as exc:
                print(f"  ✗ Could not fetch {file_path}: {exc}")
                continue

            findings_with_code.append({
                "file":         file_path,
                "line":         finding["line"],
                "matched_code": finding.get("matched_code", ""),
                "rule_message": finding.get("rule_message", ""),
                "file_content": content,
            })

        if not findings_with_code:
            print("  → No fetchable findings, skipping.\n")
            continue

        # 2. Ask AI to produce fixed file content
        prompt = build_fix_prompt(rule_id, findings_with_code)
        print("  → Calling AI for fix ...")
        try:
            raw_response = call_groq(prompt)
        except Exception as exc:
            print(f"  ✗ AI call failed: {exc}\n")
            continue

        result = parse_fix_response(raw_response)
        print(f"  → AI verdict: {result['verdict']}")

        if result["verdict"] == "FALSE_POSITIVE":
            print("  → False positive — no PR needed.\n")
            continue

        if result["verdict"] == "UNKNOWN":
            print("  ✗ Could not parse AI response — skipping PR.\n")
            print("  Raw response preview:", raw_response[:300])
            continue

        # 3. Create a fix branch from the tip of the default branch
        branch_name = f"fix/semgrep-issue-{issue_number}"
        print(f"  → Creating branch '{branch_name}' ...")
        try:
            base_sha = get_branch_sha(default_branch)
            create_branch(branch_name, base_sha)
        except urllib.error.HTTPError as exc:
            if exc.code == 422:
                print(f"  ⚠ Branch '{branch_name}' already exists, reusing.")
            else:
                print(f"  ✗ Could not create branch: {exc}\n")
                continue
        except Exception as exc:
            print(f"  ✗ Could not create branch: {exc}\n")
            continue

        # 4. Commit each fixed file onto the new branch
        committed_files: list[str] = []
        for file_path, new_content in result["files"].items():
            sha = file_shas.get(file_path)
            if sha is None:
                print(f"  ✗ No blob SHA for '{file_path}', cannot commit.")
                continue
            print(f"  → Committing fix for {file_path} ...")
            try:
                commit_file(
                    file_path,
                    new_content,
                    sha,
                    branch_name,
                    f"fix(security): fix {rule_id} in {file_path} — resolves #{issue_number}",
                )
                committed_files.append(file_path)
            except Exception as exc:
                print(f"  ✗ Commit failed for {file_path}: {exc}")

        if not committed_files:
            print("  → Nothing committed — skipping PR.\n")
            continue

        # 5. Open a PR: fix branch → default branch
        files_list = "\n".join(f"- `{fp}`" for fp in committed_files)
        pr_title   = f"[Security Fix] {rule_id} — resolves #{issue_number}"
        pr_body    = f"""## 🤖 Automated Security Fix

This PR was generated automatically by the Semgrep + AI pipeline.

| Field | Value |
|---|---|
| **Rule** | `{rule_id}` |
| **Related issue** | #{issue_number} |
| **Files changed** | see below |

### Changed files
{files_list}

---

> ⚠️ **Please review every change carefully before merging.**
> AI-generated fixes may be incomplete or introduce new issues.
> Do not merge without manual verification.

---
*Generated by `ai_fix.py` · Powered by Groq · llama-3.3-70b-versatile*
"""
        print("  → Opening PR ...")
        try:
            pr     = open_pr(pr_title, pr_body, branch_name, default_branch)
            pr_url = pr["html_url"]
            print(f"  ✓ PR created: {pr_url}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            print(f"  ✗ Could not open PR (HTTP {exc.code}): {body}\n")
            continue
        except Exception as exc:
            print(f"  ✗ Could not open PR: {exc}\n")
            continue

        # 6. Post the PR link as a comment on the issue
        issue_comment = (
            f"## 🔧 AI Fix Ready for Review\n\n"
            f"A fix for this finding has been prepared automatically.\n\n"
            f"**Pull Request:** {pr_url}\n\n"
            f"Please review the changes and merge the PR if the fix looks correct.\n\n"
            f"---\n"
            f"*Generated by `ai_fix.py` · Powered by Groq · llama-3.3-70b-versatile*"
        )
        try:
            post_issue_comment(issue_number, issue_comment)
            print(f"  ✓ PR link posted on issue #{issue_number}")
        except Exception as exc:
            print(f"  ✗ Could not comment on issue: {exc}")

        print()

    print("AI fix complete.")


if __name__ == "__main__":
    main()
