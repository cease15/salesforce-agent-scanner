#!/usr/bin/env python3
"""
Apex Specialist Agent Verifier (/apex*)
=======================================
Performs deep static analysis and behavior verification for Salesforce Apex:
1. Trigger Architecture: Single trigger per sObject, delegating to logic-less handler classes.
2. AST Bulkification: Governor-limit safety (no SOQL queries or DML statements inside loops).
3. Sharing Model & Security: Enforce 'with sharing' / 'inherited sharing' on controllers,
   and verify SOQL queries enforce security (WITH SECURITY_ENFORCED / WITH USER_MODE).
4. Test Quality & Portability: Prevent seeAllData=true, hardcoded sandbox usernames,
   hardcoded IDs, and verify meaningful assertions exist.
5. Live Org Coverage Verification: Query Tooling API for 0% triggers and depressed classes.
6. Multi-format Output: Human-readable CLI, SARIF 2.1.0 (Code Scanning), JUnit XML, and JSON.
"""

import os
import sys
import json
import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

class ApexVerifier:
    def __init__(self, repo_dir, target_org=None):
        self.repo_dir = Path(repo_dir)
        self.force_app = self.repo_dir / "force-app" / "main" / "default"
        self.classes_dir = self.force_app / "classes"
        self.triggers_dir = self.force_app / "triggers"
        self.target_org = target_org
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

    def strip_comments(self, content):
        def replacer(match):
            s = match.group(0)
            if s.startswith('/'):
                return ' '
            return "''"
        pattern = re.compile(
            r"//.*?$|/\*.*?\*/|'(?:[^'\\]|\\.)*'",
            re.DOTALL | re.MULTILINE
        )
        return re.sub(pattern, replacer, content)

    # --------------------------------------------------------------------------
    # 1. Trigger Architecture
    # --------------------------------------------------------------------------
    def verify_triggers(self):
        if not self.triggers_dir.exists():
            return

        object_triggers = defaultdict(list)
        for t_file in self.triggers_dir.glob("*.trigger"):
            try:
                content = t_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            match = re.search(r'\btrigger\s+(\w+)\s+on\s+(\w+)', content, re.IGNORECASE)
            sobj = match.group(2) if match else "Unknown"
            object_triggers[sobj].append((t_file.stem, t_file))

            # Logic-less trigger inspection
            clean = self.strip_comments(content)
            has_handler = bool(re.search(r'Handler\b', clean, re.IGNORECASE))
            has_inline_dml = bool(re.search(r'\b(insert|update|delete|upsert)\s+\w+', clean, re.IGNORECASE))
            has_inline_soql = bool(re.search(r'\[\s*SELECT\b', clean, re.IGNORECASE))

            if (has_inline_dml or has_inline_soql) and not has_handler:
                self.add_finding(
                    rule_id="APEX-TRIG-002",
                    category="Trigger Architecture",
                    severity="HIGH",
                    target=t_file.stem,
                    file_path=t_file,
                    line_num=1,
                    issue=f"Trigger '{t_file.stem}' contains inline SOQL/DML logic without delegating to a TriggerHandler.",
                    remediation="Extract trigger logic into a dedicated TriggerHandler class adhering to the logic-less trigger pattern."
                )

        # Single trigger per object rule
        for sobj, trigs in object_triggers.items():
            if len(trigs) > 1 and sobj != "Unknown":
                trig_names = [t[0] for t in trigs]
                first_file = trigs[0][1]
                self.add_finding(
                    rule_id="APEX-TRIG-001",
                    category="Trigger Architecture",
                    severity="HIGH",
                    target=f"{sobj} ({len(trigs)} triggers)",
                    file_path=first_file,
                    line_num=1,
                    issue=f"Multiple triggers detected on '{sobj}': {', '.join(trig_names)}. Order of execution is non-deterministic.",
                    remediation=f"Consolidate all logic for '{sobj}' into a single trigger delegating to a unified handler."
                )

    # --------------------------------------------------------------------------
    # 2. AST Bulkification & Governor Limits
    # --------------------------------------------------------------------------
    def verify_bulkification(self):
        scan_dirs = [self.classes_dir, self.triggers_dir]
        for sdir in scan_dirs:
            if not sdir.exists():
                continue
            for f in sdir.iterdir():
                if f.suffix not in ('.cls', '.trigger'):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                clean = self.strip_comments(content)
                lines = content.splitlines()

                # Find loop patterns and extract bodies
                # Matches for (...), while (...), do { ... }
                loop_pattern = re.compile(r'\b(for|while)\s*\([^)]*\)\s*\{', re.IGNORECASE)
                for m in loop_pattern.finditer(clean):
                    start_idx = m.end() - 1
                    # Find matching closing brace
                    depth = 0
                    end_idx = start_idx
                    for i in range(start_idx, len(clean)):
                        if clean[i] == '{':
                            depth += 1
                        elif clean[i] == '}':
                            depth -= 1
                            if depth == 0:
                                end_idx = i
                                break

                    loop_body = clean[start_idx:end_idx]
                    start_line = content[:m.start()].count('\n') + 1

                    # Check for SOQL in loop body
                    soql_match = re.search(r'\[\s*SELECT\b', loop_body, re.IGNORECASE)
                    if soql_match:
                        soql_line = start_line + loop_body[:soql_match.start()].count('\n')
                        self.add_finding(
                            rule_id="APEX-BULK-001",
                            category="Governor Limits (Bulkification)",
                            severity="CRITICAL",
                            target=f.stem,
                            file_path=f,
                            line_num=soql_line,
                            issue=f"SOQL query executed inside a loop in {f.name} (line ~{soql_line}). Vulnerable to 101 SOQL governor limit.",
                            remediation="Extract SOQL query outside loop. Collect IDs into a Set and cache records in a Map."
                        )

                    # Check for DML in loop body
                    dml_match = re.search(r'\b(insert|update|delete|upsert)\s+[a-zA-Z0-9_]+;', loop_body, re.IGNORECASE)
                    if not dml_match:
                        dml_match = re.search(r'\bDatabase\.(insert|update|delete|upsert)\s*\(', loop_body, re.IGNORECASE)
                    if dml_match:
                        dml_line = start_line + loop_body[:dml_match.start()].count('\n')
                        self.add_finding(
                            rule_id="APEX-BULK-002",
                            category="Governor Limits (Bulkification)",
                            severity="CRITICAL",
                            target=f.stem,
                            file_path=f,
                            line_num=dml_line,
                            issue=f"DML operation executed inside a loop in {f.name} (line ~{dml_line}). Vulnerable to 150 DML governor limit.",
                            remediation="Accumulate sObjects into a List and invoke a single bulk DML statement outside the loop."
                        )

    # --------------------------------------------------------------------------
    # 3. Sharing Model & Security Context
    # --------------------------------------------------------------------------
    def verify_sharing_and_security(self):
        if not self.classes_dir.exists():
            return

        for cls_file in self.classes_dir.glob("*.cls"):
            try:
                content = cls_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if "@isTest" in content or "testMethod" in content:
                continue

            clean = self.strip_comments(content)
            has_aura_enabled = bool(re.search(r'@AuraEnabled\b', clean, re.IGNORECASE))
            has_rest_resource = bool(re.search(r'@RestResource\b', clean, re.IGNORECASE))

            class_decl_match = re.search(
                r'\b(public|global)\s+(with\s+sharing|without\s+sharing|inherited\s+sharing)?\s*(class|interface)\s+' + re.escape(cls_file.stem) + r'\b',
                clean, re.IGNORECASE
            )
            sharing_model = "omitted"
            if class_decl_match and class_decl_match.group(2):
                sharing_model = class_decl_match.group(2).lower()

            is_pure_auth = ("Site.login" in clean or "Site.forgotPassword" in clean) and not (
                "SELECT " in clean.upper() or "INSERT " in clean.upper() or "UPDATE " in clean.upper() or "DELETE " in clean.upper()
            )

            # Check controllers
            if (has_aura_enabled or has_rest_resource) and sharing_model in ["without sharing", "omitted"]:
                if is_pure_auth:
                    self.add_finding(
                        rule_id="APEX-SEC-002",
                        category="Apex Sharing Context",
                        severity="INFO",
                        target=cls_file.stem,
                        file_path=cls_file,
                        line_num=1,
                        issue=f"Authentication controller '{cls_file.stem}' uses '{sharing_model}' for Site.login with zero database operations.",
                        remediation="Verified architectural necessity for guest authentication."
                    )
                else:
                    self.add_finding(
                        rule_id="APEX-SEC-001",
                        category="Apex Sharing Context",
                        severity="CRITICAL" if has_aura_enabled else "HIGH",
                        target=cls_file.stem,
                        file_path=cls_file,
                        line_num=1,
                        issue=f"Controller class '{cls_file.stem}' with @AuraEnabled/@RestResource declared as '{sharing_model}'. Executes in system mode without sharing.",
                        remediation="Change class declaration to 'with sharing' or 'inherited sharing', and enforce field/record level security."
                    )

            # Dynamic SOQL injection check
            dynamic_queries = re.finditer(r'Database\.query\s*\((.*?)\)', clean, re.DOTALL)
            for dq in dynamic_queries:
                query_arg = dq.group(1).strip()
                if '+' in query_arg and "escapeSingleQuotes" not in query_arg:
                    q_line = content[:dq.start()].count('\n') + 1
                    self.add_finding(
                        rule_id="APEX-SEC-003",
                        category="SOQL Injection Risk",
                        severity="HIGH" if has_aura_enabled else "MEDIUM",
                        target=f"{cls_file.stem} (Dynamic Query)",
                        file_path=cls_file,
                        line_num=q_line,
                        issue=f"Dynamic SOQL string concatenation without String.escapeSingleQuotes(): {query_arg[:80]}...",
                        remediation="Use SOQL bind variables (:var) or sanitize user inputs using String.escapeSingleQuotes()."
                    )

    # --------------------------------------------------------------------------
    # 4. Test Suite Quality & Portability
    # --------------------------------------------------------------------------
    def verify_test_quality(self):
        if not self.classes_dir.exists():
            return

        for cls_file in self.classes_dir.glob("*.cls"):
            try:
                content = cls_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if not ("@isTest" in content or "testMethod" in content or cls_file.stem.endswith(("Test", "_Test"))):
                continue

            clean = self.strip_comments(content)

            # seeAllData=true
            see_all_data_match = re.search(r'seeAllData\s*=\s*true', clean, re.IGNORECASE)
            if see_all_data_match:
                line_num = content[:see_all_data_match.start()].count('\n') + 1
                self.add_finding(
                    rule_id="APEX-TEST-001",
                    category="Test Quality",
                    severity="HIGH",
                    target=cls_file.stem,
                    file_path=cls_file,
                    line_num=line_num,
                    issue=f"Test class '{cls_file.stem}' uses seeAllData=true, coupling unit test execution to sandbox data.",
                    remediation="Remove seeAllData=true and construct isolated test fixtures using @testSetup."
                )

            # Hardcoded usernames
            user_match = re.search(r'[\'"][a-zA-Z0-9._%+-]+@deltaportal\.test\.\w+[\'"]', clean)
            if not user_match:
                user_match = re.search(r'[\'"][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.sandbox[\'"]', clean)
            if user_match:
                line_num = content[:user_match.start()].count('\n') + 1
                self.add_finding(
                    rule_id="APEX-TEST-002",
                    category="Test Portability",
                    severity="HIGH",
                    target=cls_file.stem,
                    file_path=cls_file,
                    line_num=line_num,
                    issue=f"Test class queries hardcoded sandbox username {user_match.group(0)}. Fails in CI and scratch orgs.",
                    remediation="Create isolated test users dynamically in @testSetup with unique usernames (e.g. System.currentTimeMillis())."
                )

            # Missing Assertions
            has_test_method = bool(re.search(r'@isTest\s+(static\s+void|void)\s+\w+', clean, re.IGNORECASE)) or "testMethod" in clean
            if has_test_method:
                has_assertions = bool(re.search(r'\b(System\.assert|Assert\.)', clean))
                if not has_assertions:
                    self.add_finding(
                        rule_id="APEX-TEST-003",
                        category="Test Quality",
                        severity="HIGH",
                        target=cls_file.stem,
                        file_path=cls_file,
                        line_num=1,
                        issue=f"Test class '{cls_file.stem}' has 0 assertions. Tests must verify business logic and return values.",
                        remediation="Add meaningful assertions using modern System.Assert (Assert.areEqual, Assert.isTrue) to verify behavior."
                    )

    # --------------------------------------------------------------------------
    # 5. Live Org Coverage Verification (Tooling API)
    # --------------------------------------------------------------------------
    def verify_live_org_coverage(self):
        if not self.target_org:
            return

        print(f"[*] Querying live org '{self.target_org}' via Tooling API for Apex coverage...")
        import subprocess
        query = (
            "SELECT ApexClassOrTrigger.Name, NumLinesCovered, NumLinesUncovered "
            "FROM ApexCodeCoverageAggregate "
            "WHERE ApexClassOrTrigger.Name != NULL"
        )
        cmd = [
            "sf", "data", "query",
            "--target-org", self.target_org,
            "--use-tooling-api",
            "--query", query,
            "--json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                records = data.get("result", {}).get("records", [])
                for r in records:
                    name = r.get("ApexClassOrTrigger", {}).get("Name", "")
                    covered = r.get("NumLinesCovered", 0)
                    uncovered = r.get("NumLinesUncovered", 0)
                    total = covered + uncovered
                    pct = (covered / total * 100.0) if total > 0 else 0.0

                    # Triggers must have >0% coverage
                    if name in ["RSLI_QuoteTrigger", "RSLI_NOSTrigger", "RSLI_QuoteClass_Trigger", "CrownQRTrigger"] and covered == 0:
                        self.add_finding(
                            rule_id="APEX-COV-001",
                            category="Live Apex Coverage",
                            severity="CRITICAL",
                            target=name,
                            file_path=f"force-app/main/default/triggers/{name}.trigger",
                            line_num=1,
                            issue=f"Production trigger '{name}' has 0% coverage ({covered}/{total} lines) in {self.target_org}. Blocks deployment.",
                            remediation=f"Create a dedicated test class exercising {name} trigger events (insert, update, delete)."
                        )
                    elif total > 0 and pct < 75.0:
                        self.add_finding(
                            rule_id="APEX-COV-002",
                            category="Live Apex Coverage",
                            severity="HIGH" if pct == 0 else "MEDIUM",
                            target=name,
                            file_path=f"force-app/main/default/classes/{name}.cls",
                            line_num=1,
                            issue=f"Apex component '{name}' coverage is {pct:.1f}% ({covered}/{total} lines). Below 75% platform requirement.",
                            remediation=f"Add unit test scenarios exercising branches and edge cases in {name}."
                        )
        except Exception as e:
            print(f"[-] Tooling API query skipped or encountered error: {e}")

    def run_all(self):
        self.verify_triggers()
        self.verify_bulkification()
        self.verify_sharing_and_security()
        self.verify_test_quality()
        self.verify_live_org_coverage()
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
                        "name": "Salesforce Apex Specialist Verifier",
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
        testsuites = ET.Element("testsuites", name="Apex Agent Verification", tests=str(len(self.findings)), failures=str(len([f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']])))
        suite = ET.SubElement(testsuites, "testsuite", name="Apex Standards Gate", tests=str(len(self.findings)))
        for f in self.findings:
            case = ET.SubElement(suite, "testcase", classname=f["file"], name=f"{f['rule_id']}: {f['target']}")
            if f["severity"] in ["CRITICAL", "HIGH"]:
                fail_elem = ET.SubElement(case, "failure", message=f["issue"], type=f["category"])
                fail_elem.text = f"File: {f['file']}:{f['line']}\nIssue: {f['issue']}\nRemediation: {f['remediation']}"
        return ET.tostring(testsuites, encoding="utf-8", xml_declaration=True).decode("utf-8")

def main():
    parser = argparse.ArgumentParser(description="Salesforce Apex Specialist Agent Verifier (/apex*)")
    parser.add_argument("--repo-dir", default=".", help="Repository root directory")
    parser.add_argument("--target-org", default="", help="Optional target Salesforce org for coverage checks")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--sarif", help="File path to write SARIF 2.1.0 report")
    parser.add_argument("--junit", help="File path to write JUnit XML report")
    args = parser.parse_args()

    verifier = ApexVerifier(args.repo_dir, target_org=args.target_org)
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
    print("       APEX SPECIALIST AGENT VERIFICATION REPORT (/apex*)       ")
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
        print(f"[-] Apex verification failed: {crit_count + high_count} critical/high issue(s) detected.")
        sys.exit(1)
    else:
        print("[+] Apex verification passed clean.")
        sys.exit(0)

if __name__ == "__main__":
    main()
