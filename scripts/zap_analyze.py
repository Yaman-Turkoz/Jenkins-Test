#!/usr/bin/env python3
"""
scripts/zap_analyze.py
======================
Analyses XSS findings from a ZAP DAST report using the Groq LLM,
then opens a single GitHub Issue containing all true positives with their PoCs.

This is the Jenkins pipeline equivalent of the
ai_analyze.py + create_issues.py pair used in the GitHub Actions workflow.

Usage:
    python3 zap_analyze.py --report zap-report.json --output zap-analysis.json

Required environment variables:
    GROQ_API_KEY   : Groq API key
    GITHUB_TOKEN   : GitHub PAT with repo + issues scope
    GITHUB_REPO    : Repository in "owner/repo" format (e.g. Yaman-Turkoz/Jenkins-Test)
"""

import argparse
import json
import os
import sys
import time

import requests

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

GROQ_API_URL  = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL    = "llama-3.3-70b-versatile"
GITHUB_API    = "https://api.github.com"

# Only process these ZAP rule IDs (scope defined by mentor: XSS only)
XSS_RULE_IDS = {"40012", "40014", "40016", "40017"}

# Risk code -> label
RISK_LABELS = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}


# ─────────────────────────────────────────────────────────────────────────────
# ZAP Report Parsing
# ─────────────────────────────────────────────────────────────────────────────

def load_zap_alerts(report_path: str) -> list:
    """
    Extracts XSS alerts from a ZAP traditional-json report.

    ZAP JSON structure:
      {"site": [{"alerts": [{"pluginid": "...", "instances": [...]}]}]}

    Each instance is returned as a separate finding
    (different URL/parameter combinations).
    """
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            plugin_id = str(alert.get("pluginid", ""))
            if plugin_id not in XSS_RULE_IDS:
                continue

            risk_code = str(alert.get("riskcode", "0"))

            for instance in alert.get("instances", []):
                alerts.append({
                    "rule_id":    plugin_id,
                    "name":       alert.get("name", "XSS"),
                    "risk":       RISK_LABELS.get(risk_code, "Unknown"),
                    "confidence": alert.get("confidence", "Unknown"),
                    "desc":       alert.get("desc", ""),
                    "solution":   alert.get("solution", ""),
                    "uri":        instance.get("uri", ""),
                    "method":     instance.get("method", "GET"),
                    "param":      instance.get("param", ""),
                    "attack":     instance.get("attack", ""),
                    "evidence":   instance.get("evidence", ""),
                    "otherinfo":  instance.get("otherinfo", ""),
                })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Groq AI Analysis
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an experienced web application security engineer.
You review XSS alerts found by ZAP DAST and determine
whether each one is a true positive or a false positive.

Return ONLY valid JSON. Do not write anything else, add explanations,
or use markdown code blocks."""

def build_user_prompt(finding: dict) -> str:
    return f"""Analyse the following ZAP XSS finding:

Rule     : {finding['name']} (ID: {finding['rule_id']})
Risk     : {finding['risk']} | Confidence: {finding['confidence']}
URL      : {finding['uri']}
Method   : {finding['method']}
Parameter: {finding['param']}
Payload  : {finding['attack']}
Evidence : {finding['evidence']}
Desc     : {finding['desc'][:400]}

Response format (this JSON only, nothing else):
{{
  "verdict": "true_positive" or "false_positive",
  "reasoning": "Short explanation -- why TP or FP? (max 2 sentences)",
  "poc": "Full curl command or browser URL that reproduces the attack",
  "severity": "High" or "Medium" or "Low"
}}"""


def analyze_with_groq(finding: dict, api_key: str, retries: int = 2) -> dict:
    """
    Analyses a finding using the Groq LLM.
    Retries up to `retries` times on failure.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":       GROQ_MODEL,
        "messages":    [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": build_user_prompt(finding)},
        ],
        "temperature": 0.1,   # low temperature -> consistent JSON output
        "max_tokens":  512,
    }

    for attempt in range(1, retries + 2):
        try:
            resp = requests.post(
                GROQ_API_URL,
                headers=headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()

            # The LLM sometimes wraps the response in a ```json ... ``` block; strip it
            if "```" in raw:
                parts = raw.split("```")
                # take the block after the first ```
                raw = parts[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            return json.loads(raw)

        except (requests.RequestException, json.JSONDecodeError, KeyError) as exc:
            if attempt <= retries:
                print(f"         WARNING: Groq attempt {attempt} failed: {exc} -- retrying...")
                time.sleep(2)
            else:
                raise RuntimeError(f"Groq analysis failed after {retries + 1} attempts: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Issue Creation
# ─────────────────────────────────────────────────────────────────────────────

def build_issue_body(true_positives: list) -> str:
    """Builds the GitHub Issue body as Markdown."""
    lines = [
        "## ZAP DAST: XSS Vulnerabilities Detected",
        "",
        f"> This issue was automatically created by the Jenkins DAST pipeline.  ",
        f"> **Total True Positives:** {len(true_positives)}",
        "",
        "---",
    ]

    for i, entry in enumerate(true_positives, 1):
        fd = entry["finding"]
        ai = entry["analysis"]

        lines += [
            "",
            f"### Finding #{i} -- {fd['name']}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Rule ID** | `{fd['rule_id']}` |",
            f"| **Risk** | {fd['risk']} |",
            f"| **AI Severity** | {ai.get('severity', '-')} |",
            f"| **Confidence** | {fd['confidence']} |",
            f"| **URL** | `{fd['uri']}` |",
            f"| **HTTP Method** | `{fd['method']}` |",
            f"| **Parameter** | `{fd['param']}` |",
            f"| **ZAP Payload** | `{fd['attack']}` |",
            f"| **Evidence** | `{fd['evidence']}` |",
            "",
            f"**AI Assessment:**  ",
            f"{ai.get('reasoning', '_No assessment available._')}",
            "",
            "**Proof of Concept (PoC):**",
            "```",
            ai.get('poc', fd['attack']),
            "```",
            "",
        ]

        # Append the suggested fix if present (first 400 characters)
        solution = fd.get("solution", "").strip()
        if solution:
            lines += [
                "**Suggested Fix:**",
                f"> {solution[:400]}",
                "",
            ]

        lines.append("---")

    lines += [
        "",
        "<sub>Tool: OWASP ZAP | AI: Groq LLM | Automation: Jenkins Pipeline</sub>",
    ]

    return "\n".join(lines)


def create_github_issue(
    repo: str,
    token: str,
    true_positives: list,
    build_number: str = "",
) -> str:
    """Opens a GitHub Issue for true positive findings and returns its URL."""

    tp_count     = len(true_positives)
    build_suffix = f" (Build #{build_number})" if build_number else ""
    title = f"[DAST] ZAP XSS Scan: {tp_count} Vulnerability/Vulnerabilities Found{build_suffix}"
    body  = build_issue_body(true_positives)

    headers = {
        "Authorization": f"token {token}",
        "Accept":        "application/vnd.github.v3+json",
        "Content-Type":  "application/json",
    }
    payload = {
        "title":  title,
        "body":   body,
        "labels": ["security", "dast", "xss"],
    }

    resp = requests.post(
        f"{GITHUB_API}/repos/{repo}/issues",
        headers=headers,
        json=payload,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()["html_url"]


# ─────────────────────────────────────────────────────────────────────────────
# Main Flow
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Validate ZAP findings with AI and open a GitHub Issue."
    )
    parser.add_argument("--report", required=True, help="Path to zap-report.json")
    parser.add_argument("--output", required=True, help="Path to write the output JSON")
    args = parser.parse_args()

    # Read environment variables
    groq_key = os.environ.get("GROQ_API_KEY", "")
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    gh_repo  = os.environ.get("GITHUB_REPO", "")
    build_no = os.environ.get("BUILD_NUMBER", "")

    if not groq_key:
        print("ERROR: GROQ_API_KEY environment variable is missing.", file=sys.stderr)
        sys.exit(1)
    if not gh_token:
        print("ERROR: GITHUB_TOKEN environment variable is missing.", file=sys.stderr)
        sys.exit(1)
    if not gh_repo:
        print("ERROR: GITHUB_REPO environment variable is missing.", file=sys.stderr)
        sys.exit(1)

    # -- 1. Load ZAP report ---------------------------------------------------
    print(f"\n[1/3] Loading ZAP report: {args.report}")
    try:
        alerts = load_zap_alerts(args.report)
    except FileNotFoundError:
        print(f"ERROR: {args.report} not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: ZAP report contains invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"    -> {len(alerts)} XSS alert instance(s) found.")

    if not alerts:
        print("    -> No XSS findings to analyse. Exiting.")
        result = {"true_positives": [], "false_positives": [], "total_alerts": 0}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        return

    # -- 2. AI analysis for each finding -------------------------------------
    print(f"\n[2/3] Starting Groq AI analysis ({len(alerts)} finding(s))...")
    true_positives  = []
    false_positives = []

    for idx, finding in enumerate(alerts, 1):
        label     = f"[{idx}/{len(alerts)}]"
        short_uri = finding["uri"][-60:] if len(finding["uri"]) > 60 else finding["uri"]
        print(f"  {label} {short_uri} -- param: '{finding['param']}'")

        try:
            analysis = analyze_with_groq(finding, groq_key)
            verdict  = analysis.get("verdict", "unknown")
            icon     = "OK" if verdict == "true_positive" else "--"
            print(f"         [{icon}] {verdict.upper()} | {analysis.get('reasoning', '')[:80]}")

            if verdict == "true_positive":
                true_positives.append({"finding": finding, "analysis": analysis})
            else:
                false_positives.append({"finding": finding, "analysis": analysis})

        except Exception as exc:
            # If AI analysis fails, treat the finding as TP (fail-safe principle)
            print(f"         [!!] AI analysis failed: {exc} -- treating finding as TP.")
            true_positives.append({
                "finding":  finding,
                "analysis": {
                    "verdict":   "true_positive",
                    "reasoning": f"AI analysis failed ({exc}); finding flagged as TP out of caution.",
                    "poc":       finding.get("attack", "Detected by ZAP."),
                    "severity":  finding.get("risk", "Medium"),
                },
            })

    print(f"\n    -> Result: {len(true_positives)} True Positive(s), {len(false_positives)} False Positive(s)")

    # Save results to file
    result = {
        "total_alerts":    len(alerts),
        "true_positives":  true_positives,
        "false_positives": false_positives,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"    -> Analysis results saved: {args.output}")

    # -- 3. GitHub Issue ------------------------------------------------------
    print(f"\n[3/3] GitHub Issue step...")

    if not true_positives:
        print("    -> No true positives found; skipping GitHub Issue.")
        return

    print(f"    -> Opening issue for {len(true_positives)} TP(s) in {gh_repo}...")
    try:
        issue_url = create_github_issue(gh_repo, gh_token, true_positives, build_no)
        print(f"    [OK] GitHub Issue opened: {issue_url}")
    except requests.HTTPError as exc:
        print(f"    [!!] Failed to open GitHub Issue (HTTP error): {exc}", file=sys.stderr)
        print(f"         Response: {exc.response.text[:300]}", file=sys.stderr)
    except Exception as exc:
        print(f"    [!!] Failed to open GitHub Issue: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
