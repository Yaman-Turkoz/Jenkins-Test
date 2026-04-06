import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
import re


GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SEMGREP_REPORT = "semgrep-report.json"
AI_OUTPUT = "ai-analysis.json"

# load semgrep

def load_semgrep_report():
    with open(SEMGREP_REPORT) as f:
        data = json.load(f)
    return data.get("results", [])

# Get Changed Files 

def get_changed_files():
    result = subprocess.run(
        ["git", "diff", "HEAD~1", "HEAD", "--name-only"],
        capture_output=True, text=True
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]

# Read File Contents (FULL CONTEXT for taint analysis)

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

# Extract Added Lines WITH Mapping (skip empty lines)

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
            code = line[1:].strip()

            # skip empty / whitespace-only lines (newline commits)
            if not code:
                new_line_num += 1
                continue

            added_lines.append({
                "file": current_file,
                "line": new_line_num,
                "code": code
            })
            new_line_num += 1

    return added_lines

# Build Prompt

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
FULL FILE CONTEXT (for taint analysis only)
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

1. You may analyze FULL FILE CONTENT for taint/dataflow.
2. You are ONLY allowed to report vulnerabilities on ADDED LINES.
3. File + line MUST EXACTLY match an entry from added_lines.
4. If not in added_lines → DO NOT REPORT.

5. A variable is USER-CONTROLLED ONLY IF:
   - It directly uses: $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES
   - OR is assigned from them in the SAME added_lines
   - OTHERWISE → SAFE

6. NEVER say "could be" or "potentially".
7. ONLY report CERTAIN vulnerabilities.
8. If unsure → DO NOT REPORT.

9. If (file + line) exists in Semgrep findings → SKIP.

10. DO NOT hallucinate flows or variables.

11. If nothing found → return empty list.

12. You MUST respond with ONLY valid JSON.
   No explanations, no markdown, no extra text.

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

# Call Groq API 

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

    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = json.loads(resp.read().decode("utf-8"))

    return raw["choices"][0]["message"]["content"]

# Parse Response (ROBUST JSON EXTRACTOR) 

def parse_response(text):
    text = text.strip()

    # remove markdown blocks if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])

    # extract JSON from noisy response
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON found in AI response")

    json_text = match.group(0)

    return json.loads(json_text)

# Post-filter (CRITICAL SAFETY)

def filter_results(ai_findings, added_lines, semgrep_findings):
    valid = []

    allowed_pairs = {
        (l["file"], l["line"])
        for l in added_lines
    }

    semgrep_pairs = {
        (f.get("path"), f.get("start", {}).get("line"))
        for f in semgrep_findings
    }

    for f in ai_findings:
        pair = (f.get("file"), f.get("line"))

        if pair not in allowed_pairs:
            continue

        if pair in semgrep_pairs:
            continue

        valid.append(f)

    return valid

# Main 

def main():
    print(f"GROQ_API_KEY present: {'YES' if GROQ_API_KEY else 'NO'}")

    if not GROQ_API_KEY:
        print("Missing GROQ_API_KEY")
        sys.exit(1)

    print("Loading Semgrep results...")
    semgrep_findings = load_semgrep_report()

    print("Detecting changed files...")
    changed_files = get_changed_files()

    print("Reading file contents...")
    file_contents = read_file_contents(changed_files)

    print("Extracting added lines...")
    added_lines = extract_added_lines_with_mapping()

    # skip AI if nothing meaningful changed
    if not added_lines:
        print("No meaningful added lines → skipping AI")

        with open(AI_OUTPUT, "w") as f:
            json.dump({
                "open_issue": False,
                "summary": "No relevant code changes",
                "additional_findings": []
            }, f, indent=2)

        return

    print("Building prompt...")
    prompt = build_prompt(semgrep_findings, added_lines, file_contents)

    print("Calling AI...")

    try:
        raw = call_groq(prompt)
    except Exception as e:
        print("AI call failed:", e)

        with open(AI_OUTPUT, "w") as f:
            json.dump({
                "open_issue": False,
                "summary": "AI skipped due to API error",
                "additional_findings": []
            }, f, indent=2)

        return

    print("Parsing response...")

    try:
        parsed = parse_response(raw)
    except Exception as e:
        print("AI response invalid:", e)

        parsed = {
            "open_issue": False,
            "summary": "AI response invalid",
            "additional_findings": []
        }

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
