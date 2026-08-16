from __future__ import annotations

import json


def render_text(report: dict) -> str:
    lines = [
        f"SkillShield risk score: {report['risk_score']}/100",
        f"Files scanned: {report['files_scanned']} | Findings: {len(report['findings'])}",
    ]
    for item in report["findings"]:
        lines += [
            "",
            f"[{item['severity'].upper()}] {item['rule_id']} {item['title']}",
            f"  {item['path']}:{item['line']}:{item['column']}",
            f"  {item['description']}",
            f"  Fix: {item['recommendation']}",
        ]
    if not report["findings"]:
        lines.append("No suspicious patterns detected. Review manually before trusting agent instructions.")
    return "\n".join(lines) + "\n"


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_sarif(report: dict) -> str:
    rules = {}
    results = []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    for item in report["findings"]:
        rules[item["rule_id"]] = {
            "id": item["rule_id"],
            "shortDescription": {"text": item["title"]},
            "fullDescription": {"text": item["description"]},
            "help": {"text": item["recommendation"]},
        }
        results.append({
            "ruleId": item["rule_id"],
            "level": levels[item["severity"]],
            "message": {"text": item["description"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": item["path"]},
                "region": {"startLine": item["line"], "startColumn": item["column"]},
            }}],
        })
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "SkillShield", "version": report["version"], "rules": list(rules.values())}},
        "results": results,
    }]}
    return json.dumps(sarif, indent=2) + "\n"
