"""
Multi-format Reporter for Salesforce Agent Scanner
Generates SARIF 2.1.0, JUnit XML, GitHub Step Summary Markdown, and Azure DevOps task commands.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

class ScanReporter:
    def __init__(self, findings=None):
        self.findings = findings or []

    def add_findings(self, findings):
        self.findings.extend(findings)

    def to_sarif(self, tool_name="Salesforce Specialist Agent Scanner", version="1.0.0"):
        rules = {}
        results = []
        severity_to_sarif = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "INFO": "note"
        }

        for f in self.findings:
            rid = f.get("rule_id", "SF-SEC-001")
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": f.get("category", "GeneralQuality").replace(" ", ""),
                    "shortDescription": {"text": f.get("category", "General Quality")},
                    "defaultConfiguration": {"level": severity_to_sarif.get(f.get("severity", "HIGH"), "warning")}
                }

            results.append({
                "ruleId": rid,
                "level": severity_to_sarif.get(f.get("severity", "HIGH"), "warning"),
                "message": {"text": f"{f.get('issue', '')}\nRemediation: {f.get('remediation', '')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(f.get("file", "")).replace("\\", "/")},
                        "region": {"startLine": max(1, f.get("line", 1))}
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "semanticVersion": version,
                        "informationUri": "https://github.com/cease15/salesforce-agent-scanner",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }
        return sarif_doc

    def to_junit(self, suite_name="Salesforce Agent Quality Gate"):
        total_tests = max(len(self.findings), 1)
        failures = len([f for f in self.findings if f.get("severity") in ["CRITICAL", "HIGH"]])
        testsuites = ET.Element("testsuites", name="Salesforce Agent Pipeline Gate", tests=str(total_tests), failures=str(failures))
        suite = ET.SubElement(testsuites, "testsuite", name=suite_name, tests=str(total_tests), failures=str(failures))

        if not self.findings:
            case = ET.SubElement(suite, "testcase", classname="SalesforceAgentScanner", name="AllGatesPassedClean")
        else:
            for f in self.findings:
                case = ET.SubElement(suite, "testcase", classname=str(f.get("file", "SalesforceApp")), name=f"{f.get('rule_id', 'RULE')}: {f.get('target', 'Target')}")
                if f.get("severity") in ["CRITICAL", "HIGH"]:
                    fail_elem = ET.SubElement(case, "failure", message=f.get("issue", ""), type=f.get("category", "Error"))
                    fail_elem.text = f"File: {f.get('file', '')}:{f.get('line', 1)}\nSeverity: {f.get('severity', '')}\nIssue: {f.get('issue', '')}\nRemediation: {f.get('remediation', '')}"
                elif f.get("severity") == "MEDIUM":
                    warn_elem = ET.SubElement(case, "skipped", message=f.get("issue", ""))
                    warn_elem.text = f"Warning: {f.get('issue', '')}"

        return ET.tostring(testsuites, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def to_markdown_summary(self, target_org="", gate_passed=True):
        crit = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in self.findings if f.get("severity") == "HIGH")
        med = sum(1 for f in self.findings if f.get("severity") == "MEDIUM")
        info = sum(1 for f in self.findings if f.get("severity") == "INFO")

        badge = "🟢 PASSED" if gate_passed else "🔴 FAILED"

        md = []
        md.append("# 🚀 Salesforce Specialist Agent CI/CD Quality Gate")
        md.append("")
        md.append(f"**Overall Status:** {badge} | **Critical:** `{crit}` | **High:** `{high}` | **Medium:** `{med}` | **Info:** `{info}`")
        if target_org:
            md.append(f"**Target Org:** `{target_org}`")
        md.append("")
        md.append("| Category | Findings | Severity |")
        md.append("| :--- | :--- | :--- |")

        # Group by category
        categories = {}
        for f in self.findings:
            c = f.get("category", "Other")
            if c not in categories:
                categories[c] = []
            categories[c].append(f)

        for c, items in sorted(categories.items()):
            max_sev = "INFO"
            if any(x.get("severity") == "CRITICAL" for x in items): max_sev = "CRITICAL"
            elif any(x.get("severity") == "HIGH" for x in items): max_sev = "HIGH"
            elif any(x.get("severity") == "MEDIUM" for x in items): max_sev = "MEDIUM"
            md.append(f"| **{c}** | `{len(items)}` finding(s) | `{max_sev}` |")

        md.append("")

        if crit > 0 or high > 0:
            md.append("### ⚠️ Blocking Pull Request Issues")
            md.append("<details><summary>Click to view critical and high severity findings</summary>\n")
            for f in self.findings:
                if f.get("severity") in ["CRITICAL", "HIGH"]:
                    md.append(f"- **[{f.get('severity')}] {f.get('rule_id')}: {f.get('target')}**")
                    md.append(f"  - **File:** `{f.get('file')}:{f.get('line', 1)}`")
                    md.append(f"  - **Issue:** {f.get('issue')}")
                    if f.get("remediation"):
                        md.append(f"  - **Remediation:** {f.get('remediation')}")
            md.append("\n</details>\n")
        else:
            md.append("> [!NOTE]\n> **ALL QUALITY GATES CLEAR**: Zero critical or high severity violations detected. Ready to merge.")

        return "\n".join(md) + "\n"

    def emit_ado_commands(self):
        commands = []
        for f in self.findings:
            sev = f.get("severity")
            msg_type = "error" if sev in ["CRITICAL", "HIGH"] else ("warning" if sev == "MEDIUM" else "info")
            file_path = f.get("file", "")
            line = f.get("line", 1)
            issue = f.get("issue", "").replace("\r", "").replace("\n", " ")
            commands.append(f"##vso[task.logissue type={msg_type};sourcepath={file_path};linenumber={line};code={f.get('rule_id', '')}]{issue}")
        return commands
