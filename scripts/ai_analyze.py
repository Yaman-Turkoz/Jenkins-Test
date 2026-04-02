import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

# ── Sabitler ──────────────────────────────────────────────────────────────────

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
SEMGREP_REPORT = "semgrep-report.json"
AI_OUTPUT      = "ai-analysis.json"

# ── 1. Semgrep raporunu oku ───────────────────────────────────────────────────
def load_semgrep_report():
    with open(SEMGREP_REPORT) as f:
        data = json.load(f)
    return data.get("results", [])

# ── 2. Son commit'te değişen dosyaları bul ────────────────────────────────────
def get_changed_files():
    result = subprocess.run(
        ["git", "diff", "HEAD~1", "HEAD", "--name-only"],
        capture_output=True, text=True
    )
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return files

# ── 3. Dosya içeriklerini oku ─────────────────────────────────────────────────
def read_file_contents(file_paths):
    contents = {}
    for path in file_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    contents[path] = f.read()
            except Exception as e:
                contents[path] = f"(okunamadı: {e})"
        else:
            contents[path] = "(dosya bulunamadı)"
    return contents

# ── 4. Gemini'ye gönderilecek prompt'u oluştur ───────────────────────────────
def build_prompt(semgrep_findings, changed_files, file_contents):
    # Değişen dosyaların diff'ini de al (satır bazında ne değişti)
    diff_result = subprocess.run(
        ["git", "diff", "HEAD~1", "HEAD"],
        capture_output=True, text=True
    )
    diff_text = diff_result.stdout or "(diff alınamadı)"

    semgrep_json = json.dumps(semgrep_findings, indent=2, ensure_ascii=False)

    files_section = ""
    for path, content in file_contents.items():
        files_section += f"\n\n### {path}\n```\n{content}\n```"

    prompt = f"""You are a security code reviewer. Analyze the following information and return ONLY a valid JSON object — no markdown, no explanation, no extra text.

## Context
The developer made changes in the last commit. Semgrep scanned only the changed parts (using --baseline-commit HEAD~1). Your job is the same: analyze ONLY whether the changes introduced in the last commit create security vulnerabilities. Do NOT report pre-existing issues in unchanged code.

## Git Diff (what changed in the last commit)
```
{diff_text[:8000]}
```

## Semgrep Findings (JSON)
```json
{semgrep_json}
```

## Changed Files (full content for context)
{files_section[:12000]}

## Your Tasks
1. Validate each Semgrep finding: is it a real vulnerability or a false positive?
2. Analyze the git diff yourself: did the changes introduce any additional vulnerabilities that Semgrep missed?
3. Decide: should a GitHub issue be opened?

## Required JSON Output Format
Return ONLY this JSON structure:
{{
  "open_issue": true or false,
  "summary": "one sentence explaining your overall decision",
  "semgrep_findings": [
    {{
      "rule_id": "the rule id from semgrep",
      "file": "path/to/file.php",
      "line": 42,
      "confirmed": true or false,
      "reason": "why you confirmed or rejected this finding"
    }}
  ],
  "additional_findings": [
    {{
      "title": "short vulnerability title",
      "file": "path/to/file.php",
      "line": 42,
      "severity": "HIGH or MEDIUM or LOW",
      "description": "what the vulnerability is and why the change introduced it"
    }}
  ]
}}

Rules:
- "open_issue" is true if there is at least one confirmed semgrep finding OR at least one additional finding with severity HIGH or MEDIUM.
- "additional_findings" can be an empty list [] if you find nothing extra.
- "semgrep_findings" can be an empty list [] if semgrep found nothing.
- Do NOT include any text outside the JSON object.
"""
    return prompt

# ── 5. Gemini API'ye istek at ─────────────────────────────────────────────────
def call_groq(prompt):
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 2048
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        GROQ_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}"
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

    try:
        text = raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        print("Groq cevabı parse edilemedi:", raw)
        sys.exit(1)

    return text

# ── 6. Gemini'nin JSON cevabını parse et ─────────────────────────────────────
def parse_groq_response(text):
    # Bazen Gemini ```json ... ``` ile sarar, temizle
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print("Groq JSON parse hatası:", e)
        print("Ham cevap:", text)
        sys.exit(1)

# ── Ana akış ──────────────────────────────────────────────────────────────────
def main():
    # main() fonksiyonunun en başına ekle
    print(f"GROQ_API_KEY var mı: {'Evet' if GROQ_API_KEY else 'HAYIR - BOŞ!'}")
    print(f"Key başlangıcı: {GROQ_API_KEY[:8] if GROQ_API_KEY else 'YOK'}")
    
    if not GROQ_API_KEY:
        print("GROQ_API_KEY bulunamadı!")
        sys.exit(1)

    print("📂 Semgrep raporu okunuyor...")
    findings = load_semgrep_report()
    print(f"   → {len(findings)} semgrep bulgusu bulundu.")

    print("📝 Değişen dosyalar tespit ediliyor...")
    changed_files = get_changed_files()
    print(f"   → Değişen dosyalar: {changed_files}")

    print("📖 Dosya içerikleri okunuyor...")
    file_contents = read_file_contents(changed_files)

    print("🤖 Groq'a gönderiliyor...")
    prompt = build_prompt(findings, changed_files, file_contents)
    raw_response = call_groq(prompt)

    print("📊 Groq cevabı parse ediliyor...")
    analysis = parse_groq_response(raw_response)

    # Kaydet
    with open(AI_OUTPUT, "w") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)

    print(f"\n✅ AI analizi tamamlandı → {AI_OUTPUT}")
    print(f"   open_issue : {analysis.get('open_issue')}")
    print(f"   summary    : {analysis.get('summary')}")
    print(f"   semgrep onaylı: {sum(1 for x in analysis.get('semgrep_findings',[]) if x.get('confirmed'))}")
    print(f"   ek bulgular   : {len(analysis.get('additional_findings', []))}")

if __name__ == "__main__":
    main()
