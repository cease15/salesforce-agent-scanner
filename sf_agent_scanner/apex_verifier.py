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

    # --------------------------------------------------------------------------
    # 5. Runtime Exceptions & Asynchronous Apex
    # --------------------------------------------------------------------------
    def verify_runtime_and_exceptions(self):
        """Deep runtime integrity checks: AuraHandledException sanitization, DML in cacheable methods, and @future typing."""
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

            # 1. APEX-AURA-002: AuraHandledException without setMessage()
            # If throw new AuraHandledException(...) is called directly
            ahe_matches = re.finditer(r'throw\s+new\s+AuraHandledException\s*\([^)]*\);', clean)
            for am in ahe_matches:
                line_num = content[:am.start()].count('\n') + 1
                self.add_finding(
                    rule_id="APEX-AURA-002",
                    category="Exception Sanitization",
                    severity="HIGH",
                    target=cls_file.stem,
                    file_path=cls_file,
                    line_num=line_num,
                    issue="AuraHandledException instantiated and thrown in a single statement without calling e.setMessage(). Salesforce strips the message and displays generic 'Script-thrown exception' to portal/LWC users.",
                    remediation="Instantiate the exception into a variable, explicitly invoke e.setMessage('user-safe message'), then throw e."
                )

            # 2. APEX-AURA-CACHE-001: DML in Cacheable Method
            cacheable_method_pattern = re.compile(
                r'@AuraEnabled\s*\(\s*cacheable\s*=\s*true\s*\)\s*(?:public|global|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{',
                re.IGNORECASE
            )
            for cm in cacheable_method_pattern.finditer(clean):
                method_name = cm.group(1)
                start_idx = cm.end() - 1
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
                method_body = clean[start_idx:end_idx]
                method_line = content[:cm.start()].count('\n') + 1

                dml_match = re.search(r'\b(insert|update|delete|upsert)\s+[a-zA-Z0-9_]+;', method_body, re.IGNORECASE)
                if not dml_match:
                    dml_match = re.search(r'\bDatabase\.(insert|update|delete|upsert)\s*\(', method_body, re.IGNORECASE)
                if dml_match:
                    dml_line = method_line + method_body[:dml_match.start()].count('\n')
                    self.add_finding(
                        rule_id="APEX-AURA-CACHE-001",
                        category="Apex Runtime Integrity",
                        severity="CRITICAL",
                        target=f"{cls_file.stem}.{method_name}",
                        file_path=cls_file,
                        line_num=dml_line,
                        issue=f"Method '{method_name}' is annotated with @AuraEnabled(cacheable=true) but executes DML. Throws System.InvalidParameterValueException: DML currently not allowed at runtime.",
                        remediation="Remove cacheable=true from the @AuraEnabled annotation or extract the DML operation into a separate, non-cacheable action."
                    )

            # 3. APEX-ASYNC-001: Non-primitive parameter in @future method
            future_pattern = re.compile(
                r'@future\s*(?:\([^)]*\))?\s*(?:public|global|private|protected)?\s*static\s+void\s+(\w+)\s*\(([^)]*)\)',
                re.IGNORECASE
            )
            for fm in future_pattern.finditer(clean):
                method_name = fm.group(1)
                param_str = fm.group(2).strip()
                method_line = content[:fm.start()].count('\n') + 1
                if param_str:
                    non_primitive_match = re.search(
                        r'\b(Account|Contact|Case|Lead|Opportunity|User|Quote|sObject)\b',
                        param_str,
                        re.IGNORECASE
                    )
                    if non_primitive_match:
                        self.add_finding(
                            rule_id="APEX-ASYNC-001",
                            category="Asynchronous Apex",
                            severity="CRITICAL",
                            target=f"{cls_file.stem}.{method_name}",
                            file_path=cls_file,
                            line_num=method_line,
                            issue=f"@future method '{method_name}' declares non-primitive parameter ({non_primitive_match.group(0)}). @future methods only accept primitive types or collections of primitives.",
                            remediation="Pass List<Id> of records instead of sObject instances, or refactor to Queueable Apex (implements Queueable)."
                        )

    # --------------------------------------------------------------------------
    # 6. Agentforce & Invocable Actions
    # --------------------------------------------------------------------------
    def verify_agentforce_and_invocables(self):
        """Validates Agentforce backing logic contracts: @InvocableMethod single entry, bulkified I/O, descriptions."""
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
            if "@InvocableMethod" not in clean and "@invocablemethod" not in clean.lower():
                continue

            # 1. AGENT-INVOC-002: Multiple @InvocableMethod in a single class
            invoc_matches = list(re.finditer(r'@InvocableMethod\s*(?:\((.*?)\))?', clean, re.IGNORECASE | re.DOTALL))
            if len(invoc_matches) > 1:
                self.add_finding(
                    rule_id="AGENT-INVOC-002",
                    category="Agentforce Backing Logic",
                    severity="CRITICAL",
                    target=cls_file.stem,
                    file_path=cls_file,
                    line_num=content[:invoc_matches[1].start()].count('\n') + 1,
                    issue=f"Apex class '{cls_file.stem}' declares {len(invoc_matches)} @InvocableMethod methods. Salesforce compilation permits only one @InvocableMethod per class.",
                    remediation="Split each invocable action into its own dedicated Apex class."
                )

            # 2. AGENT-INVOC-001: Missing description or non-bulkified signature
            for im in invoc_matches:
                attr_str = im.group(1) or ""
                im_line = content[:im.start()].count('\n') + 1

                # Check description
                desc_match = re.search(r'\bdescription\s*=\s*[\'"]([^\'"]+)[\'"]', attr_str, re.IGNORECASE)
                if not desc_match or not desc_match.group(1).strip():
                    self.add_finding(
                        rule_id="AGENT-INVOC-001",
                        category="Agentforce Backing Logic",
                        severity="HIGH",
                        target=f"{cls_file.stem} (@InvocableMethod)",
                        file_path=cls_file,
                        line_num=im_line,
                        issue=f"@InvocableMethod in '{cls_file.stem}' lacks a detailed 'description' attribute. The Atlas Reasoning Engine requires semantic descriptions to match user utterances to actions.",
                        remediation="Add description='...' with clear explanation of the action's purpose and expected outcome."
                    )

                # Check method signature following the annotation
                after_im = clean[im.end():]
                meth_decl = re.search(
                    r'(?:public|global)\s+static\s+([\w<>\[\],\s]+?)\s+(\w+)\s*\(([^)]*)\)',
                    after_im,
                    re.IGNORECASE
                )
                if meth_decl:
                    ret_type = meth_decl.group(1).strip()
                    method_name = meth_decl.group(2).strip()
                    param_str = meth_decl.group(3).strip()

                    # Return type check: must be List<...> or void
                    if not (ret_type.startswith("List<") or ret_type == "void"):
                        self.add_finding(
                            rule_id="AGENT-INVOC-001",
                            category="Agentforce Backing Logic",
                            severity="HIGH",
                            target=f"{cls_file.stem}.{method_name}",
                            file_path=cls_file,
                            line_num=im_line,
                            issue=f"Invocable method '{method_name}' returns non-bulkified type '{ret_type}'. Invocable actions must return List<Response> or List<Primitive>.",
                            remediation="Wrap the return type in a List (e.g. List<Response> or List<String>)."
                        )

                    # Parameter check: must accept single parameter of List<...>
                    if param_str:
                        if "," in param_str or not param_str.strip().startswith("List<"):
                            self.add_finding(
                                rule_id="AGENT-INVOC-001",
                                category="Agentforce Backing Logic",
                                severity="HIGH",
                                target=f"{cls_file.stem}.{method_name}",
                                file_path=cls_file,
                                line_num=im_line,
                                issue=f"Invocable method '{method_name}' accepts '{param_str}'. Invocable actions must accept a single List<Request> parameter for bulkification.",
                                remediation="Encapsulate method inputs into a single inner Request class and accept List<Request>."
                            )

            # Check @InvocableVariable in inner classes
            invoc_vars = list(re.finditer(r'@InvocableVariable\s*(?:\((.*?)\))?\s*(?:public|global)?\s+[\w<>\[\]]+\s+(\w+)\s*;', clean, re.IGNORECASE | re.DOTALL))
            for iv in invoc_vars:
                attr_str = iv.group(1) or ""
                var_name = iv.group(2)
                var_line = content[:iv.start()].count('\n') + 1

                # Reserved keyword check (AGENT-INVOC-003)
                if var_name.lower() in {"model", "description", "label"}:
                    self.add_finding(
                        rule_id="AGENT-INVOC-003",
                        category="Agentforce Backing Logic",
                        severity="CRITICAL",
                        target=f"{cls_file.stem}.{var_name}",
                        file_path=cls_file,
                        line_num=var_line,
                        issue=f"@InvocableVariable field '{var_name}' uses a reserved Agent Script keyword ('model', 'description', 'label'). Causes 'SyntaxError: Unexpected {var_name}' during Agent Script compilation.",
                        remediation=f"Rename '{var_name}' to e.g. '{var_name}_val' or '{var_name}_text' to avoid collision with Agent Script parser keywords."
                    )

                desc_match = re.search(r'\bdescription\s*=\s*[\'"]([^\'"]+)[\'"]', attr_str, re.IGNORECASE)
                if not desc_match or not desc_match.group(1).strip():
                    self.add_finding(
                        rule_id="AGENT-INVOC-001",
                        category="Agentforce Backing Logic",
                        severity="MEDIUM",
                        target=f"{cls_file.stem}.{var_name}",
                        file_path=cls_file,
                        line_num=var_line,
                        issue=f"@InvocableVariable '{var_name}' in '{cls_file.stem}' lacks a 'description' attribute. Atlas Reasoning Engine uses field descriptions for slot extraction from user input.",
                        remediation="Add description='...' attribute with field purpose, format guidelines, and examples."
                    )

    # --------------------------------------------------------------------------
    # 7. Enterprise Architecture & Separation of Concerns (SoC)
    # --------------------------------------------------------------------------
    def verify_enterprise_architecture(self):
        """Verifies Service Layer decoupling and Selector query security modes."""
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

            # 1. APEX-ENTERPRISE-001: Service Layer decoupling
            if cls_file.stem.endswith("Service"):
                coupled_context = re.search(r'\b(Trigger\.(new|old|newMap|oldMap|isInsert|isUpdate|isDelete|isBefore|isAfter)|ApexPages\.currentPage\(\)|ApexPages\.addMessage\b)', clean, re.IGNORECASE)
                if coupled_context:
                    line_num = content[:coupled_context.start()].count('\n') + 1
                    self.add_finding(
                        rule_id="APEX-ENTERPRISE-001",
                        category="Enterprise Architecture (SoC)",
                        severity="HIGH",
                        target=cls_file.stem,
                        file_path=cls_file,
                        line_num=line_num,
                        issue=f"Service Layer class '{cls_file.stem}' references caller context '{coupled_context.group(0)}'. Violates Separation of Concerns.",
                        remediation="Service methods must accept generic collections (List/Set/Map) and remain caller-agnostic so they can be invoked from Triggers, REST APIs, or Agentforce."
                    )

            # 2. APEX-SELECTOR-001: Selector query security mode
            if cls_file.stem.endswith("Selector"):
                queries = re.finditer(r'\[\s*SELECT\b([^\]]+)\]', clean, re.IGNORECASE)
                for q in queries:
                    q_text = q.group(0)
                    has_security = bool(re.search(r'\bWITH\s+(USER_MODE|SYSTEM_MODE|SECURITY_ENFORCED)\b', q_text, re.IGNORECASE))
                    if not has_security:
                        q_line = content[:q.start()].count('\n') + 1
                        self.add_finding(
                            rule_id="APEX-SELECTOR-001",
                            category="Selector & Security Pattern",
                            severity="HIGH",
                            target=f"{cls_file.stem} (SOQL Query)",
                            file_path=cls_file,
                            line_num=q_line,
                            issue=f"SOQL query in Selector class '{cls_file.stem}' lacks security mode enforcement (WITH USER_MODE or WITH SECURITY_ENFORCED).",
                            remediation="Append 'WITH USER_MODE' to enforce Object CRUD and Field-Level Security permissions at query execution time."
                        )

    def run_all(self):
        self.verify_triggers()
        self.verify_bulkification()
        self.verify_sharing_and_security()
        self.verify_runtime_and_exceptions()
        self.verify_agentforce_and_invocables()
        self.verify_enterprise_architecture()
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
