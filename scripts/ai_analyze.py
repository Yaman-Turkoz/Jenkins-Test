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

# Tool call loop limit — AI can read at most this many files per issue
MAX_TOOL_CALLS = 20


# ── GitHub API helpers ────────────────────────────────────────────────────────

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


def fetch_repo_tree() -> list[str]:
    try:
        repo_info      = gh_get(f"/repos/{REPO}")
        default_branch = repo_info.get("default_branch", "main")
        branch_data    = gh_get(f"/repos/{REPO}/branches/{default_branch}")
        tree_sha       = branch_data["commit"]["commit"]["tree"]["sha"]

        tree_data = gh_get(f"/repos/{REPO}/git/trees/{tree_sha}?recursive=1")

        return [
            item["path"]
            for item in tree_data.get("tree", [])
            if item["type"] == "blob"
            and item["path"].endswith((".php", ".js", ".py"))  # ✅ FILTER
        ]

    except Exception as exc:
        print(f"  ⚠ Could not fetch repo tree: {exc}")
        return []


# ── Groq API helper (with tool calling) ──────────────────────────────────────

# The single tool we expose to the AI
FETCH_FILE_TOOL = {
    "type": "function",
    "function": {
        "name": "fetch_file",
        "description": (
            "Read the full source of any file in the repository. "
            "Use this to trace taint flows across files — e.g. to find the caller "
            "that includes the finding file, or to locate the sink that outputs a "
            "tainted variable. You may call this tool multiple times."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repo-root-relative path to the file, e.g. 'vulnerabilities/xss_r/index.php'",
                }
            },
            "required": ["path"],
        },
    },
}


def call_groq_with_tools(messages: list) -> list:
    """
    Run a tool-calling loop with Groq.
    Returns the final messages list (including all tool exchanges).
    The last message with role='assistant' and no tool_calls is the final answer.
    """
    tool_calls_made = 0

    while True:
        payload = {
            "model":       "llama-3.3-70b-versatile",
            "messages":    messages,
            "tools":       [FETCH_FILE_TOOL],
            "tool_choice": "auto",
            "temperature": 0,
            "max_tokens":  4096,
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

        assistant_msg = raw["choices"][0]["message"]
        messages.append(assistant_msg)

        # No tool calls → AI is done
        if not assistant_msg.get("tool_calls"):
            return messages

        # Safety limit
        if tool_calls_made >= MAX_TOOL_CALLS:
            print(f"  ⚠ Reached MAX_TOOL_CALLS ({MAX_TOOL_CALLS}), stopping tool loop.")
            return messages

        # Process every tool call the AI requested in this turn
        for tc in assistant_msg["tool_calls"]:
            tool_calls_made += 1
            tc_id   = tc["id"]
            tc_name = tc["function"]["name"]

            try:
                args = json.loads(tc["function"]["arguments"])
            except Exception:
                args = {}

            if tc_name == "fetch_file":
                path = args.get("path", "")
                print(f"    🔍 AI is reading: {path}")
                content = fetch_file_content(path)
                # Truncate very large files to keep context sane
                if len(content) > 12000:
                    content = content[:12000] + "\n... (file truncated at 12 000 chars)"
                result = content
            else:
                result = f"Unknown tool: {tc_name}"

            # Append tool result back into the conversation
            messages.append({
                "role":         "tool",
                "tool_call_id": tc_id,
                "name":         tc_name,
                "content":      result,
            })

    # unreachable, but just in case
    return messages


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_initial_messages(rule_id: str, findings_with_code: list, repo_tree: list[str]) -> list:
    """
    Build the initial messages list for the tool-calling conversation.
    """
    findings_block = ""
    for idx, f in enumerate(findings_with_code, start=1):
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

**Content of the finding file:**
```php
{file_ctx}
```
"""

    tree_block = "\n".join(repo_tree) if repo_tree else "(repo tree unavailable)"

    system_prompt = f"""You are a Semgrep triage engine with the ability to read any file in the repository.

Your ONLY task is to validate whether the reported Semgrep finding represents a real vulnerability
by tracing the complete taint flow — even if that flow spans multiple files.

## How to use your file-reading tool
- You have access to a `fetch_file` tool. Call it whenever you need to read a file.
- If the finding file only assigns a tainted value to a variable (e.g. `$html .= ...`) without
  echoing it, search for the file that includes this one or outputs that variable.
- Use the repository file tree below to locate candidates, then fetch and read them.
- You may call `fetch_file` as many times as needed (up to {MAX_TOOL_CALLS} calls total).
- Stop fetching once you have enough context to reach a confident verdict.

## File selection guidance
- Prefer files that are likely entry points, such as:
  - index.php
  - router files
  - controllers
  - files that include or require other files

## Repository file tree (filtered)

{tree_block}

## Scope rules — read carefully
- Your analysis scope is STRICTLY LIMITED to the vulnerability type indicated by rule `{rule_id}`.
- You may only report issues that are directly related to the findings listed below.
- DO NOT mention unrelated vulnerabilities, suggest unrelated fixes, or expand scope.

## Output format

## Verdict
For EACH finding:
- State TRUE POSITIVE or FALSE POSITIVE
- You MUST explicitly identify the SINK:
  - Sink variable
  - Sink function (e.g. echo, print, response.write, etc.)
  - Exact file path and line number where the sink occurs
- If the sink is in another file, you MUST name that file

A finding CANNOT be marked as TRUE POSITIVE unless a concrete sink is identified.
If no sink is found after reasonable exploration, mark it as FALSE POSITIVE.

## Fix
*(Omit entirely if all findings are FALSE POSITIVE.)*
Concrete before/after PHP code fix for each true-positive finding.

## Proof of Concept
*(Omit entirely if all findings are FALSE POSITIVE.)*
Step-by-step PoC including exact HTTP request or browser payload.

## Code Flow
*(Omit entirely if all findings are FALSE POSITIVE.)*

You MUST describe the FULL taint flow including:

- Source (user input)
- Intermediate variables (if any)
- Final sink

For EACH step include:
- Variable name
- File path
- Line number

The FINAL step MUST clearly identify the sink.

Example:
$_GET['q'] (search.php:10)
→ $query (search.php:12)
→ $html (renderer.php:8)
→ echo $html (templates/view.php:42)  ← SINK

Do not add any commentary outside these sections.
"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Semgrep triggered rule `{rule_id}` on these finding(s):\n\n{findings_block}\n\nBegin your analysis. Fetch any additional files you need before writing your verdict."},
    ]


def extract_final_answer(messages: list) -> str:
    """
    Extract the last assistant text message (the final answer after all tool calls).
    """
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and not msg.get("tool_calls"):
            content = msg.get("content", "")
            if content:
                return content
    return "(no answer produced)"


# ── Comment formatter ─────────────────────────────────────────────────────────

def format_comment(rule_id: str, analysis_text: str) -> str:
    return f"""## 🤖 AI Security Analysis

> **Rule:** `{rule_id}`
> This analysis was generated automatically. Always verify findings manually before acting on them.

---

{analysis_text}

---
*Powered by Groq · llama-3.3-70b-versatile*
"""


# ── Main ──────────────────────────────────────────────────────────────────────

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

    if not os.path.exists(CREATED_ISSUES_FILE):
        print(f"{CREATED_ISSUES_FILE} not found — nothing to analyse.")
        return

    with open(CREATED_ISSUES_FILE) as f:
        issues = json.load(f)

    if not issues:
        print("No issues to analyse.")
        return

    # Fetch the repo file tree once — shared across all issues
    print("\nFetching repository file tree ...")
    repo_tree = fetch_repo_tree()
    print(f"  {len(repo_tree)} files found in repo.\n")

    print(f"Found {len(issues)} issue(s) to analyse.\n")

    for issue in issues:
        issue_number = issue["issue_number"]
        rule_id      = issue["rule_id"]
        findings     = issue["findings"]

        print(f"─── Issue #{issue_number}  (rule: {rule_id}) ───")

        # Fetch the finding files upfront
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

        # Build the initial conversation and run the tool-calling loop
        messages = build_initial_messages(rule_id, findings_with_code, repo_tree)

        print(f"  → Starting AI analysis (tool calling enabled) ...")
        try:
            final_messages = call_groq_with_tools(messages)
            analysis_text  = extract_final_answer(final_messages)
        except Exception as exc:
            print(f"  ✗ AI call failed: {exc}")
            analysis_text = f"AI analysis could not be completed due to an API error:\n```\n{exc}\n```"

        # Post the comment
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
