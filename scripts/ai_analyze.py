import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

# ── Constants ────────────────────────────────────────────────────────────────

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SEMGREP_REPORT = "semgrep-report.json"
AI_OUTPUT = "ai-analysis.json"

# ── 1. Load Semgrep Report ───────────────────────────────────────────────────

def load_semgrep_report():
    with open(SEMGREP_REPORT) as f:
        data = json.load(f)
    return data.get("results", [])

# ── 2. Get Changed Files ─────────────────────────────────────────────────────

def get_changed_files():
    result = subprocess.run(
        ["git", "diff", "HEAD~1", "HEAD", "--name-only"],
        capture_output=True, text=True
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]

# ── 3. Read File Contents (FULL CONTEXT for taint analysis) ──────────────────

def read_file_contents(file_paths):
    contents = {}
    for path in file_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    contents[path] = f.read()
            except Exception as e:
                contents[path] = f"(error reading file: {e})"
        else:
            contents[path] = "(file not found)"
    return contents

# ── 4. Extract Added Lines WITH Exact File + Line Mapping ────────────────────

def extract_added_lines_with_mapping():
    result = subprocess.run(
        ["git", "diff", "--unified=0", "HEAD~1", "HEAD"],
        capture_output=True, text=True
    )

    diff = result.stdout
    added_lines = []

    current_file = None
    new_line_num = 0

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            parts = line.split(" ")
            new_part = [p for p in parts if p.startswith("+")][0]
            new_line_num = int(new_part.split(",")[0][1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append({
                "file": current_file,
                "line": new_line_num,
                "code": line[1:]
            })
            new_line_num += 1

    return added_lines

# ── 5. Build Prompt ─────────────────────────────────────────────────────────

def build_prompt(semgrep_findings, added_lines, file_contents):

    semgrep_list = []
    for f in semgrep_findings:
        semgrep_list.append({
            "file": f.get("path"),
            "line": f.get("start", {}).get("line"),
            "rule": f.get("check_id", "")
        })

    prompt = f"""
You are a strict security analyzer.

Your task is to find vulnerabilities that Semgrep MISSED.

────────────────────────────────────────
CONTEXT (for taint analysis ONLY)
────────────────────────────────────────
{json.dumps(file_contents, indent=2)[:12000]}

────────────────────────────────────────
ADDED LINES (ONLY THESE CAN BE REPORTED)
────────────────────────────────────────
{json.dumps(added_lines, indent=2)}

────────────────────────────────────────
SEMGREP FINDINGS (DO NOT DUPLICATE)
────────────────────────────────────────
{json.dumps(semgrep_list, indent=2)}

────────────────────────────────────────
STRICT RULES (MUST FOLLOW)
────────────────────────────────────────

1. You may analyze the FULL FILE CONTENT for taint/dataflow understanding.
2. HOWEVER, you are ONLY allowed to report vulnerabilities that exist EXACTLY on the "added_lines".
3. The "file" and "line" MUST match EXACTLY one entry from added_lines.
4. If it is not in added_lines → DO NOT report it.

5. A variable is considered USER-CONTROLLED ONLY IF:
   - It directly uses: $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES
   - OR is directly assigned from them in the SAME added_lines
   - OTHERWISE → treat it as SAFE

6. NEVER assume "could be vulnerable" or "potentially vulnerable".
7. ONLY report if vulnerability is CERTAIN based on the code.
8. If unsure → DO NOT REPORT.

9. If (file + line) already exists in Semgrep findings → DO NOT REPORT.

10. DO NOT hallucinate variables, flows, or sources.

11. If no valid findings → return empty list.

────────────────────────────────────────
OUTPUT FORMAT (STRICT JSON ONLY)
────────────────────────────────────────

{{
  "open_issue": false,
  "summary": "short explanation",
  "additional_findings": [
    {{
      "title": "short vulnerability title",
      "file": "exact/file/path.php",
      "line": 42,
      "severity": "HIGH or MEDIUM",
      "description": "clear explanation referencing the exact added line"
    }}
  ]
}}
"""
    return prompt

# ── 6. Call Groq API ────────────────────────────────────────────────────────

def call_groq(prompt):
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 2048
    }

    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        GROQ_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "User-Agent": "python-urllib/3.11"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"Groq API error: {e.code} {e.reason}")
        print(e.read().decode())
        sys.exit(1)

    return raw["choices"][0]["message"]["content"]

# ── 7. Parse Response ───────────────────────────────────────────────────────

def parse_response(text):
    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print("Failed to parse AI response:")
        print(text)
        sys.exit(1)

# ── 8. Post-filter (CRITICAL SAFETY) ────────────────────────────────────────

def filter_results(ai_findings, added_lines, semgrep_findings):
    valid = []

    semgrep_pairs = {
        (f.get("path"), f.get("start", {}).get("line"))
        for f in semgrep_findings
    }

    allowed_pairs = {
        (l["file"], l["line"])
        for l in added_lines
    }

    for f in ai_findings:
        pair = (f.get("file"), f.get("line"))

        if pair not in allowed_pairs:
            continue

        if pair in semgrep_pairs:
            continue

        valid.append(f)

    return valid

# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if not GROQ_API_KEY:
        print("GROQ_API_KEY missing!")
        sys.exit(1)

    print("Loading Semgrep results...")
    semgrep_findings = load_semgrep_report()

    print("Detecting changed files...")
    changed_files = get_changed_files()

    print("Reading file contents...")
    file_contents = read_file_contents(changed_files)

    print("Extracting added lines...")
    added_lines = extract_added_lines_with_mapping()

    if not added_lines:
        print("No added lines → skipping AI analysis.")
        with open(AI_OUTPUT, "w") as f:
            json.dump({
                "open_issue": False,
                "summary": "No changes to analyze",
                "additional_findings": []
            }, f, indent=2)
        return

    print("Building prompt...")
    prompt = build_prompt(semgrep_findings, added_lines, file_contents)

    print("Calling AI...")
    raw = call_groq(prompt)

    print("Parsing response...")
    parsed = parse_response(raw)

    print("Filtering results...")
    filtered = filter_results(
        parsed.get("additional_findings", []),
        added_lines,
        semgrep_findings
    )

    final_output = {
        "open_issue": len(filtered) > 0,
        "summary": parsed.get("summary", ""),
        "additional_findings": filtered
    }

    with open(AI_OUTPUT, "w") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)

    print(f"Done → {AI_OUTPUT}")
    print(f"Findings: {len(filtered)}")

if __name__ == "__main__":
    main()
