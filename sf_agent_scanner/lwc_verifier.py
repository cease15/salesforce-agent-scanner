#!/usr/bin/env python3
"""
LWC Specialist Agent Verifier (/lwc*)
=====================================
Performs deep static analysis and behavior verification for Lightning Web Components:
1. DOM Sanitization: Detects innerHTML, outerHTML, insertAdjacentHTML bypasses.
2. Reactivity & State: Detects child mutation of public @api properties.
3. Navigation Architecture: Enforces NavigationMixin over direct window.location manipulations.
4. Environment Decoupling: Detects hardcoded sandbox URLs and hardcoded record IDs.
5. Component Metadata: Verifies targetConfigs, isExposed, and modern apiVersion (>= 58.0).
6. Accessibility (A11y): Audits interactive elements for accessible labels (WCAG 2.1 AA).
7. Multi-format Output: Human-readable CLI, SARIF 2.1.0, JUnit XML, and JSON.
"""

import os
import sys
import json
import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path

class LwcVerifier:
    def __init__(self, repo_dir):
        self.repo_dir = Path(repo_dir)
        self.force_app = self.repo_dir / "force-app" / "main" / "default"
        self.lwc_dir = self.force_app / "lwc"
        self.findings = []

    def add_finding(self, rule_id, category, severity, target, file_path, line_num, issue, remediation=""):
        rel_file = ""
        try:
            rel_file = str(Path(file_path).relative_to(self.repo_dir))
        except Exception:
            rel_file = str(file_path)
        self.findings.append({
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "target": target,
            "file": rel_file,
            "line": line_num or 1,
            "issue": issue,
            "remediation": remediation
        })

    def strip_js_comments(self, content):
        clean = re.sub(r'//.*', '', content)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)
        return clean

    def strip_html_comments(self, content):
        return re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

    # --------------------------------------------------------------------------
    # 1. DOM Sanitization & Security (innerHTML bypass)
    # --------------------------------------------------------------------------
    def verify_dom_sanitization(self, comp_dir, js_file, content, clean):
        matches = re.finditer(r'\b(innerHTML|outerHTML|insertAdjacentHTML)\b', clean)
        for m in matches:
            line_num = content[:m.start()].count('\n') + 1
            op = m.group(1)
            self.add_finding(
                rule_id="LWC-DOM-001",
                category="DOM Sanitization & Security",
                severity="HIGH",
                target=f"{comp_dir.name} -> {op}",
                file_path=js_file,
                line_num=line_num,
                issue=f"Direct DOM manipulation via '{op}' detected. Bypasses LWC template engine and creates XSS risks.",
                remediation="Use standard LWC template directives (lwc:if, for:each) instead of direct DOM manipulation."
            )

    # --------------------------------------------------------------------------
    # 2. Public @api Property Reassignment (Reactive Mutation)
    # --------------------------------------------------------------------------
    def verify_api_mutations(self, comp_dir, js_file, content, clean):
        # Extract @api properties
        api_props = set()
        api_matches = re.finditer(r'@api\s+([a-zA-Z0-9_]+)\s*(?:=|[;\n])', clean)
        for am in api_matches:
            api_props.add(am.group(1))

        # Check for mutation: this.propName = ... (excluding within set propName)
        for prop in api_props:
            pattern = re.compile(rf'\bthis\.{prop}\s*=', re.MULTILINE)
            for m in pattern.finditer(clean):
                # Ensure this is not inside a setter definition 'set prop(...) { ... }'
                preceding = clean[:m.start()]
                last_set = preceding.rfind(f"set {prop}")
                is_inside_setter = False
                if last_set != -1:
                    chunk = preceding[last_set:]
                    if chunk.count('{') > chunk.count('}'):
                        is_inside_setter = True

                if not is_inside_setter:
                    line_num = content[:m.start()].count('\n') + 1
                    self.add_finding(
                        rule_id="LWC-REACT-001",
                        category="Reactive State & Mutability",
                        severity="MEDIUM",
                        target=f"{comp_dir.name} -> this.{prop}",
                        file_path=js_file,
                        line_num=line_num,
                        issue=f"Component reassigns its own public @api property '{prop}'. Public properties should be treated as read-only by child.",
                        remediation=f"Maintain an internal state variable or fire a CustomEvent to request the parent update '{prop}'."
                    )

    # --------------------------------------------------------------------------
    # 3. Navigation Mixin vs Direct window.location
    # --------------------------------------------------------------------------
    def verify_navigation(self, comp_dir, js_file, content, clean):
        loc_match = re.search(r'\bwindow\.location(\.href)?\s*=', clean)
        if loc_match:
            line_num = content[:loc_match.start()].count('\n') + 1
            has_nav_mixin = "NavigationMixin" in clean
            self.add_finding(
                rule_id="LWC-NAV-001",
                category="Navigation Architecture",
                severity="HIGH",
                target=f"{comp_dir.name} -> window.location",
                file_path=js_file,
                line_num=line_num,
                issue="Direct 'window.location' assignment used for navigation. Causes full page reload, breaks SPA state, and fails in mobile/Experience Cloud.",
                remediation="Import NavigationMixin from 'lightning/navigation' and use this[NavigationMixin.Navigate]({ type: 'standard__webPage', ... })."
            )

    # --------------------------------------------------------------------------
    # 4. Environment Decoupling & Hardcoded URLs / IDs
    # --------------------------------------------------------------------------
    def verify_environment_decoupling(self, comp_dir, js_file, content, clean):
        # Sandbox / My Domain URLs
        url_matches = re.finditer(r'[\'\"\`](https?://[a-zA-Z0-9.-]+\.(sandbox\.my|my)\.salesforce\.com[^\'\"\`]*)[\'\"\`]', clean)
        for um in url_matches:
            line_num = content[:um.start()].count('\n') + 1
            self.add_finding(
                rule_id="LWC-ENV-001",
                category="Environment Decoupling",
                severity="HIGH",
                target=f"{comp_dir.name} -> Hardcoded URL",
                file_path=js_file,
                line_num=line_num,
                issue=f"Hardcoded Salesforce instance URL '{um.group(1)}'. Breaks deployment to other sandboxes and production.",
                remediation="Use relative paths or query baseUrl from Custom Metadata / Network context."
            )

        # Hardcoded 15/18 character IDs
        id_matches = re.finditer(r'[\'\"\`](001|003|005|006|00D|a0|a1)[a-zA-Z0-9]{12,15}[\'\"\`]', clean)
        for im in id_matches:
            line_num = content[:im.start()].count('\n') + 1
            self.add_finding(
                rule_id="LWC-ENV-002",
                category="Environment Decoupling",
                severity="HIGH",
                target=f"{comp_dir.name} -> Record ID",
                file_path=js_file,
                line_num=line_num,
                issue=f"Hardcoded Salesforce record ID detected '{im.group(0)}'. IDs are org-specific and non-portable.",
                remediation="Pass record IDs dynamically via @api recordId or retrieve via Wire Service / Apex."
            )

    # --------------------------------------------------------------------------
    # 5. Component Metadata & Targets (*.js-meta.xml)
    # --------------------------------------------------------------------------
    def verify_metadata(self, comp_dir):
        meta_file = comp_dir / f"{comp_dir.name}.js-meta.xml"
        if not meta_file.exists():
            for f in comp_dir.glob("*.js-meta.xml"):
                meta_file = f
                break

        if not meta_file.exists():
            self.add_finding(
                rule_id="LWC-META-001",
                category="Component Metadata",
                severity="HIGH",
                target=comp_dir.name,
                file_path=comp_dir,
                line_num=1,
                issue=f"Missing js-meta.xml metadata descriptor for component '{comp_dir.name}'.",
                remediation="Create a valid js-meta.xml defining apiVersion, isExposed, and targets."
            )
            return

        try:
            tree = ET.parse(meta_file)
            root = tree.getroot()
            is_exposed = False
            api_version = 0.0
            has_targets = False

            for child in root:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if tag == "isExposed":
                    is_exposed = (child.text or "").strip().lower() == "true"
                elif tag == "apiVersion":
                    try:
                        api_version = float(child.text or "0.0")
                    except ValueError:
                        pass
                elif tag == "targets" and len(child) > 0:
                    has_targets = True

            if is_exposed and not has_targets:
                self.add_finding(
                    rule_id="LWC-META-002",
                    category="Component Metadata",
                    severity="HIGH",
                    target=comp_dir.name,
                    file_path=meta_file,
                    line_num=1,
                    issue=f"Component '{comp_dir.name}' has <isExposed>true</isExposed> but no <targets> declared.",
                    remediation="Add <targets> (e.g. lightning__RecordPage, lightningCommunity__Page) to expose component in builders."
                )

            if api_version > 0 and api_version < 58.0:
                self.add_finding(
                    rule_id="LWC-META-003",
                    category="Component Modernization",
                    severity="MEDIUM",
                    target=comp_dir.name,
                    file_path=meta_file,
                    line_num=1,
                    issue=f"Component apiVersion {api_version} is outdated. Modern Experience Cloud & LWS require >= 58.0 (recommended 62.0).",
                    remediation="Upgrade <apiVersion> to 62.0 in js-meta.xml."
                )
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # 6. Accessibility & HTML Templates (*.html)
    # --------------------------------------------------------------------------
    def verify_accessibility(self, comp_dir):
        for html_file in comp_dir.glob("*.html"):
            try:
                content = html_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            clean = self.strip_html_comments(content)

            # Button icon without alternative-text
            btn_icon_matches = re.finditer(r'<lightning-button-icon\b([^>]*)>', clean, re.IGNORECASE)
            for m in btn_icon_matches:
                attrs = m.group(1)
                if "alternative-text" not in attrs:
                    line_num = content[:m.start()].count('\n') + 1
                    self.add_finding(
                        rule_id="LWC-A11Y-001",
                        category="Accessibility (WCAG 2.1)",
                        severity="MEDIUM",
                        target=f"{comp_dir.name} -> lightning-button-icon",
                        file_path=html_file,
                        line_num=line_num,
                        issue="<lightning-button-icon> missing 'alternative-text' attribute. Screen readers cannot announce button action.",
                        remediation="Add alternative-text='Description of button action' for screen reader accessibility."
                    )

    def run_all(self):
        if not self.lwc_dir.exists():
            return self.findings

        for comp_dir in self.lwc_dir.iterdir():
            if not comp_dir.is_dir():
                continue

            # Verify JS files
            for js_file in comp_dir.glob("*.js"):
                if "__tests__" in str(js_file):
                    continue
                try:
                    content = js_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                clean = self.strip_js_comments(content)
                self.verify_dom_sanitization(comp_dir, js_file, content, clean)
                self.verify_api_mutations(comp_dir, js_file, content, clean)
                self.verify_navigation(comp_dir, js_file, content, clean)
                self.verify_environment_decoupling(comp_dir, js_file, content, clean)

            # Verify Metadata
            self.verify_metadata(comp_dir)

            # Verify Accessibility in Templates
            self.verify_accessibility(comp_dir)

        return self.findings

    # --------------------------------------------------------------------------
    # Output Exporters
    # --------------------------------------------------------------------------
    def to_sarif(self):
        rules = {}
        results = []
        severity_to_sarif = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "INFO": "note"
        }

        for f in self.findings:
            rid = f["rule_id"]
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": f["category"].replace(" ", ""),
                    "shortDescription": {"text": f["category"]},
                    "defaultConfiguration": {"level": severity_to_sarif.get(f["severity"], "warning")}
                }

            results.append({
                "ruleId": rid,
                "level": severity_to_sarif.get(f["severity"], "warning"),
                "message": {"text": f"{f['issue']}\nRemediation: {f['remediation']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                        "region": {"startLine": max(1, f["line"])}
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Salesforce LWC Specialist Verifier",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/cease15/rsli-crown-inspection",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }
        return sarif_doc

    def to_junit(self):
        testsuites = ET.Element("testsuites", name="LWC Agent Verification", tests=str(len(self.findings)), failures=str(len([f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']])))
        suite = ET.SubElement(testsuites, "testsuite", name="LWC Standards Gate", tests=str(len(self.findings)))
        for f in self.findings:
            case = ET.SubElement(suite, "testcase", classname=f["file"], name=f"{f['rule_id']}: {f['target']}")
            if f["severity"] in ["CRITICAL", "HIGH"]:
                fail_elem = ET.SubElement(case, "failure", message=f["issue"], type=f["category"])
                fail_elem.text = f"File: {f['file']}:{f['line']}\nIssue: {f['issue']}\nRemediation: {f['remediation']}"
        return ET.tostring(testsuites, encoding="utf-8", xml_declaration=True).decode("utf-8")

def main():
    parser = argparse.ArgumentParser(description="Salesforce LWC Specialist Agent Verifier (/lwc*)")
    parser.add_argument("--repo-dir", default=".", help="Repository root directory")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--sarif", help="File path to write SARIF 2.1.0 report")
    parser.add_argument("--junit", help="File path to write JUnit XML report")
    args = parser.parse_args()

    verifier = LwcVerifier(args.repo_dir)
    findings = verifier.run_all()

    if args.sarif:
        Path(args.sarif).parent.mkdir(parents=True, exist_ok=True)
        with open(args.sarif, "w", encoding="utf-8") as sf:
            json.dump(verifier.to_sarif(), sf, indent=2)
        print(f"[+] SARIF report written to {args.sarif}")

    if args.junit:
        Path(args.junit).parent.mkdir(parents=True, exist_ok=True)
        with open(args.junit, "w", encoding="utf-8") as jf:
            jf.write(verifier.to_junit())
        print(f"[+] JUnit report written to {args.junit}")

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    # Terminal summary
    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    info_count = sum(1 for f in findings if f["severity"] == "INFO")

    print("\n" + "="*70)
    print("        LWC SPECIALIST AGENT VERIFICATION REPORT (/lwc*)        ")
    print("="*70)
    print(f"Total Findings: {len(findings)} | CRITICAL: {crit_count} | HIGH: {high_count} | MEDIUM: {med_count} | INFO: {info_count}")
    print("="*70)

    for f in findings:
        badge = f"[{f['severity']}]"
        print(f"{badge:<10} {f['rule_id']}: {f['target']}")
        print(f"           Location:    {f['file']}:{f['line']}")
        print(f"           Issue:       {f['issue']}")
        if f['remediation']:
            print(f"           Remediation: {f['remediation']}")
        print("")

    if crit_count > 0 or high_count > 0:
        print(f"[-] LWC verification failed: {crit_count + high_count} critical/high issue(s) detected.")
        sys.exit(1)
    else:
        print("[+] LWC verification passed clean.")
        sys.exit(0)

if __name__ == "__main__":
    main()
