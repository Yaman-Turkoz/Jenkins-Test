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

ZAP_CREATED_ISSUES = "zap-created-issues.json"


# GitHub API helpers
def _gh_headers():
    return {
        "Authorization":        f"Bearer {GH_TOKEN}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "zap-ai-analyze/1.0",
    }


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
def build_analysis_prompt(alert_name: str, plugin_id: str, risk_level: str,
                           confidence: str, description: str, solution: str,
                           instances: list) -> str:

    instances_block = ""
    for idx, inst in enumerate(instances, start=1):
        other_section = ""
        if inst.get("otherinfo", "").strip():
            other_section = f"- **Additional Info:** {inst['otherinfo'].strip()}\n"

        instances_block += f"""
### Instance {idx}
- **URL:** `{inst['uri']}`
- **HTTP Method:** `{inst['method']}`
- **Vulnerable Parameter:** `{inst['param']}`
- **ZAP Attack Payload:** `{inst['attack']}`
- **Evidence in Response:** `{inst['evidence']}`
{other_section}"""

return f"""You are a DAST (Dynamic Application Security Testing) findings triage engine.
Your ONLY task is to validate whether the ZAP-reported finding represents a real, exploitable vulnerability.

ZAP detected alert `{alert_name}` (Plugin ID: {plugin_id}).

**Scan Metadata:**
- Risk Level reported by ZAP: {risk_level}
- Confidence reported by ZAP: {confidence}

**ZAP Description:**
{description}

**Detected Instances:**
{instances_block}

---

IMPORTANT SCOPE RULES:
Your analysis is STRICTLY LIMITED to the vulnerability type reported above.
DO NOT mention any other vulnerabilities or security issues outside this finding.

VALIDATION RULES:
- If the exact attack payload appears in the evidence field, this is very strong confirmation of a TRUE POSITIVE.
- Consider the injection context: tag body, attribute value, JavaScript context, etc.
- HTML entity encoding (e.g. &lt;script&gt;) in the evidence means the payload was sanitized — lean toward FALSE POSITIVE.
- Raw payload in evidence with no encoding means the XSS fires — TRUE POSITIVE.
- ZAP Confidence "Confirmed" or "High" should be weighted heavily toward TRUE POSITIVE.
- Only classify as FALSE POSITIVE if there is clear evidence of proper output encoding or the payload cannot execute in its reflection context.

DO NOT:
- Mention unrelated vulnerabilities or suggest fixing unrelated issues.
- Provide Severity, PoC, Fix, or Attack Flow sections for FALSE POSITIVE instances.
- Speculate about other potential attack vectors outside this specific finding.

---

Analyze every instance carefully and produce the following sections.
Reference actual parameter names, URLs, and payload values from the data above.

The structure below repeats **per TRUE POSITIVE instance**.
FALSE POSITIVE instances only appear in the Verdict section with a brief explanation — they have no further sections.

## Verdict
For each instance, state clearly: **TRUE POSITIVE** or **FALSE POSITIVE**.
Explain why in 2-3 sentences referencing the actual evidence.
Format strictly as:
**Instance N:** TRUE POSITIVE / FALSE POSITIVE — explanation.
(one instance per line, blank line between each)

---

Then, for each TRUE POSITIVE instance, output the following four sections.
Use the exact heading format shown, replacing N with the instance number.
Separate each instance block with a horizontal rule (---).

## Severity — Instance N
Provide a severity rating: **Critical / High / Medium / Low**.
Include a CVSS v3.1 base score estimate and vector string.
Justify by addressing: authentication required, user interaction needed,
scope of impact, and whether session hijacking or account takeover is achievable.

## Proof of Concept — Instance N
Write a step-by-step PoC for an attacker to exploit this specific instance.
Include the exact HTTP request (method, URL, headers, full payload).
Describe the expected browser-side effect (alert dialog, cookie theft, etc.).
If session hijacking is feasible, include that payload as well.

## Fix — Instance N
Provide a concrete server-side fix for this specific instance.
Show a before/after code snippet in PHP.
Include a Content-Security-Policy header example as defense-in-depth.
Write all code in a single code block.

## Attack Flow — Instance N
Show the data flow from user input to the XSS sink using arrows (tree, top to bottom).
Reference the actual parameter, endpoint, and reflection point.
Write the flow in a single code block.
Example format:
    HTTP GET /page?param=<script>alert(1)</script>
        ↓
    Server reads: $_GET['param']  (no sanitization)
        ↓
    Output: echo $param  (raw reflection into HTML body)
        ↓
    Browser parses: <script>alert(1)</script>
        ↓
    JavaScript executes: alert(1)

---
Respond **only** with the sections above. Do not add any commentary outside them.
"""


# Comment formatter
def format_comment(alert_name: str, plugin_id: str, analysis_text: str) -> str:
    return f"""## 🤖 AI Security Analysis — ZAP Finding

> **Alert:** `{alert_name}` (Plugin ID: `{plugin_id}`)
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

    if not os.path.exists(ZAP_CREATED_ISSUES):
        print(f"{ZAP_CREATED_ISSUES} not found — nothing to analyse.")
        return

    with open(ZAP_CREATED_ISSUES) as f:
        issues = json.load(f)

    if not issues:
        print("No ZAP issues to analyse.")
        return

    print(f"\nFound {len(issues)} issue(s) to analyse.\n")

    for issue in issues:
        issue_number = issue["issue_number"]
        alert_name   = issue["alert_name"]
        plugin_id    = issue["plugin_id"]
        risk_level   = issue["risk_level"]
        confidence   = issue["confidence"]
        description  = issue["description"]
        solution     = issue["solution"]
        instances    = issue["instances"]

        print(f"─── Issue #{issue_number}  (alert: {alert_name}) ───")

        prompt = build_analysis_prompt(
            alert_name  = alert_name,
            plugin_id   = plugin_id,
            risk_level  = risk_level,
            confidence  = confidence,
            description = description,
            solution    = solution,
            instances   = instances,
        )

        print(f"  → Calling AI ...")
        try:
            analysis_text = call_groq(prompt)
        except Exception as exc:
            print(f"  ✗ AI call failed: {exc}")
            analysis_text = (
                f"AI analysis could not be completed due to an API error:\n```\n{exc}\n```"
            )

        comment_body = format_comment(alert_name, plugin_id, analysis_text)

        print(f"  → Posting comment on issue #{issue_number} ...")
        try:
            gh_post_comment(issue_number, comment_body)
            print(f"  ✓ Comment posted on issue #{issue_number}")
        except Exception as exc:
            print(f"  ✗ Failed to post comment: {exc}")

    print("\nZAP AI analysis complete.")


if __name__ == "__main__":
    main()
