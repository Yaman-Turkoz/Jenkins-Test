import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

GITHUB_API = "https://api.github.com"
GH_TOKEN   = os.environ.get("GH_TOKEN", "")
REPO       = os.environ.get("REPO", "")

ZAP_REPORT_FILE    = "zap/dvwa-xss-report-json.json"
ZAP_CREATED_ISSUES = "zap-created-issues.json"

RISK_MAP = {
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Informational",
}

CONFIDENCE_MAP = {
    "4": "Confirmed",
    "3": "High",
    "2": "Medium",
    "1": "Low",
}

PLUGIN_TITLES = {
    "40012": "Cross Site Scripting (Reflected)",
    "40014": "Cross Site Scripting (Persistent)",
    "40016": "Cross Site Scripting (Persistent) - Prime",
    "40017": "Cross Site Scripting (Persistent) - Spider",
}


# GitHub API helpers
def _gh_headers():
    return {
        "Authorization":        f"Bearer {GH_TOKEN}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":           "zap-create-issues/1.0",
        "Content-Type":         "application/json",
    }


def ensure_label(label_name: str, color: str = "d73a4a") -> None:
    """Create the label if it does not already exist."""
    check_url = f"{GITHUB_API}/repos/{REPO}/labels/{urllib.parse.quote(label_name)}"
    req = urllib.request.Request(check_url, headers=_gh_headers())
    try:
        urllib.request.urlopen(req, timeout=15)
        return  # label already exists
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    create_url = f"{GITHUB_API}/repos/{REPO}/labels"
    payload    = json.dumps({"name": label_name, "color": color}).encode()
    req        = urllib.request.Request(
        create_url, data=payload, headers=_gh_headers(), method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        print(f"Label '{label_name}' created.")
    except Exception as exc:
        print(f"Warning: could not create label '{label_name}': {exc}")


def gh_create_issue(title: str, body: str, labels: list) -> dict:
    url     = f"{GITHUB_API}/repos/{REPO}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    req     = urllib.request.Request(
        url, data=payload, headers=_gh_headers(), method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def main():
    print(f"GH_TOKEN present : {'YES' if GH_TOKEN else 'NO'}")
    print(f"REPO             : {REPO}")

    if not GH_TOKEN:
        print("ERROR: Missing GH_TOKEN")
        sys.exit(1)
    if not REPO:
        print("ERROR: Missing REPO")
        sys.exit(1)

    if not os.path.exists(ZAP_REPORT_FILE):
        print(f"{ZAP_REPORT_FILE} not found — nothing to process.")
        return

    with open(ZAP_REPORT_FILE) as f:
        zap_data = json.load(f)

    # Collect all alerts from all sites
    all_alerts = []
    for site in zap_data.get("site", []):
        all_alerts.extend(site.get("alerts", []))

    created_issues = []

    if not all_alerts:
        print("ZAP: No findings — no issues will be opened.")
    else:
        ensure_label("security")
        ensure_label("zap")

        print(f"\nFound {len(all_alerts)} alert type(s).\n")

        for alert in all_alerts:
            plugin_id   = alert.get("pluginid", "")
            alert_name  = alert.get("name", alert.get("alert", "Unknown Alert"))
            risk_code   = str(alert.get("riskcode", "0"))
            confidence  = str(alert.get("confidence", "2"))
            risk_level  = RISK_MAP.get(risk_code, "Unknown")
            conf_label  = CONFIDENCE_MAP.get(confidence, "Unknown")
            description = alert.get("desc", "").strip()
            solution    = alert.get("solution", "").strip()
            reference   = alert.get("reference", "").strip()
            cwe_id      = alert.get("cweid", "")
            wasc_id     = alert.get("wascid", "")
            instances   = alert.get("instances", [])

            title = f"[ZAP] {alert_name}"

            # Build instances markdown table
            instances_md = (
                "| # | Method | URL | Parameter | Attack Payload | Evidence |\n"
                "|---|--------|-----|-----------|----------------|----------|\n"
            )
            structured_instances = []

            for idx, inst in enumerate(instances, start=1):
                uri      = inst.get("uri", "")
                method   = inst.get("method", "GET")
                param    = inst.get("param", "—")
                attack   = inst.get("attack", "").replace("|", "\\|")
                evidence = inst.get("evidence", "").replace("|", "\\|")
                other    = inst.get("otherinfo", "")

                instances_md += (
                    f"| {idx} | `{method}` | `{uri}` | `{param}` "
                    f"| `{attack}` | `{evidence}` |\n"
                )
                structured_instances.append({
                    "uri":       uri,
                    "method":    method,
                    "param":     param,
                    "attack":    attack,
                    "evidence":  evidence,
                    "otherinfo": other,
                })

            refs_md = ""
            if reference:
                refs_md = "\n### References\n"
                for line in reference.strip().splitlines():
                    line = line.strip()
                    if line:
                        refs_md += f"- {line}\n"

            body = f"""## ZAP Security Finding

| Field | Value |
|-------|-------|
| **Plugin ID** | `{plugin_id}` |
| **Risk Level** | {risk_level} |
| **Confidence** | {conf_label} |
| **CWE** | [CWE-{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id}.html) |
| **WASC** | {wasc_id} |

### Detected Instances ({len(structured_instances)})

{instances_md}
{refs_md}
---
*This issue was opened automatically by the ZAP pipeline stage.*
"""

            print(f"  → Creating issue: {title}")
            try:
                issue_data   = gh_create_issue(title, body, ["security", "zap"])
                issue_number = issue_data["number"]
                issue_url    = issue_data["html_url"]
                print(f"  ✓ Issue #{issue_number} created: {issue_url}")

                created_issues.append({
                    "issue_number": issue_number,
                    "alert_name":   alert_name,
                    "plugin_id":    plugin_id,
                    "risk_level":   risk_level,
                    "confidence":   conf_label,
                    "description":  description,
                    "solution":     solution,
                    "instances":    structured_instances,
                })
            except Exception as exc:
                print(f"  ✗ Failed to create issue for '{alert_name}': {exc}")

    with open(ZAP_CREATED_ISSUES, "w") as f:
        json.dump(created_issues, f, indent=2, ensure_ascii=False)

    print(f"\n{len(created_issues)} issue(s) written to {ZAP_CREATED_ISSUES}")
    print("All ZAP findings have been processed.")


if __name__ == "__main__":
    main()
