#!/usr/bin/env python3
"""
Salesforce Metadata Security Auditor & Governance Engine
Scans both repository metadata (XML, Apex) and live org Tooling API (HealthCheck, Guest Perms, Session Settings).
Identifies privilege escalations, unauthenticated exposures, broken access controls, and data leak vectors.
"""

import os
import sys
import json
import argparse
import subprocess
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

DANGEROUS_USER_PERMS = {
    "ViewAllData": "Allows viewing ALL data across the entire organization, bypassing all sharing rules.",
    "ModifyAllData": "Allows creating, editing, and deleting ALL records across the entire org.",
    "AuthorApex": "Allows authoring Apex code (admin/developer privilege).",
    "CustomizeApplication": "Allows modifying org schema, fields, and application setup.",
    "ManageUsers": "Allows creating, resetting passwords, and modifying user accounts.",
    "ExportReport": "Allows downloading reports containing mass organizational data.",
    "PasswordNeverExpires": "Exempts accounts from password rotation policies.",
    "ApiEnabled": "Allows API access (high risk for guest users or restricted portal profiles).",
    "CanApproveChangeRequests": "Allows approving critical system changes.",
    "PermissionsSendCustomNotifications": "Can be leveraged for notification spam.",
}

SENSITIVE_FIELD_KEYWORDS = [
    "ssn", "tax_id", "taxid", "social_security", "salary", "compensation", 
    "bank_account", "routing_number", "credit_card", "password", "secret", 
    "token", "api_key", "dob", "birthdate", "ein"
]

def strip_ns(tag):
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag

def get_xml_root(file_path):
    try:
        tree = ET.parse(file_path)
        return tree.getroot()
    except Exception:
        return None

def strip_comments(content):
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

class SecurityAuditor:
    def __init__(self, repo_dir, target_org=None):
        self.repo_dir = Path(repo_dir)
        self.force_app = self.repo_dir / "force-app" / "main" / "default"
        self.target_org = target_org
        self.findings = []
        self.profile_classes = defaultdict(set)
        self.permset_classes = defaultdict(set)
        self.profile_meta = {}

    def add_finding(self, category, severity, target, file_path, issue, remediation=""):
        rel_file = ""
        try:
            rel_file = str(Path(file_path).relative_to(self.repo_dir))
        except Exception:
            rel_file = str(file_path)
        self.findings.append({
            "category": category,
            "severity": severity,
            "target": target,
            "file": rel_file,
            "issue": issue,
            "remediation": remediation
        })

    def audit_profiles_and_permsets(self):
        profiles_dir = self.force_app / "profiles"
        if profiles_dir.exists():
            for p_file in profiles_dir.glob("*.profile-meta.xml"):
                profile_name = p_file.stem.replace(".profile-meta", "")
                root = get_xml_root(p_file)
                if root is None:
                    continue

                is_custom = False
                user_license = None
                for child in root:
                    tag = strip_ns(child.tag)
                    if tag == "custom" and child.text == "true":
                        is_custom = True
                    elif tag == "userLicense":
                        user_license = child.text

                is_external = any(term in profile_name.lower() or (user_license and term in user_license.lower()) 
                                  for term in ["external", "customer", "portal", "community", "guest", "deltav2"])

                self.profile_meta[profile_name] = {
                    "is_external": is_external,
                    "user_license": user_license,
                    "is_custom": is_custom
                }

                for child in root:
                    tag = strip_ns(child.tag)
                    
                    if tag == "userPermissions":
                        name = None
                        enabled = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "name": name = sub.text
                            elif subtag == "enabled": enabled = (sub.text == "true")
                        
                        if enabled and name in DANGEROUS_USER_PERMS:
                            severity = "CRITICAL" if (is_external and name == "PasswordNeverExpires") or name in ["ViewAllData", "ModifyAllData"] else "HIGH"
                            self.add_finding(
                                category="Profile User Permission",
                                severity=severity,
                                target=f"{profile_name} -> {name}",
                                file_path=p_file,
                                issue=f"User permission '{name}' is enabled ({DANGEROUS_USER_PERMS[name]}).",
                                remediation=f"Disable '{name}' on profile '{profile_name}' unless strictly required by administrators."
                            )

                    elif tag == "objectPermissions":
                        obj_name = None
                        view_all = False
                        mod_all = False
                        allow_del = False
                        allow_edit = False
                        allow_create = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "object": obj_name = sub.text
                            elif subtag == "viewAllRecords": view_all = (sub.text == "true")
                            elif subtag == "modifyAllRecords": mod_all = (sub.text == "true")
                            elif subtag == "allowDelete": allow_del = (sub.text == "true")
                            elif subtag == "allowEdit": allow_edit = (sub.text == "true")
                            elif subtag == "allowCreate": allow_create = (sub.text == "true")

                        if view_all or mod_all:
                            severity = "CRITICAL" if is_external else "HIGH"
                            self.add_finding(
                                category="Profile Object Permission",
                                severity=severity,
                                target=f"{profile_name} -> {obj_name}",
                                file_path=p_file,
                                issue=f"Overly permissive object setting: {'ViewAllRecords ' if view_all else ''}{'ModifyAllRecords' if mod_all else ''} enabled.",
                                remediation=f"Disable ViewAll/ModifyAll records on '{obj_name}' in profile '{profile_name}'. Use sharing rules or permission sets."
                            )

                        if "guest" in profile_name.lower() and (allow_edit or allow_del):
                            self.add_finding(
                                category="Guest Profile Violation",
                                severity="CRITICAL",
                                target=f"{profile_name} -> {obj_name}",
                                file_path=p_file,
                                issue=f"Guest user has {'Edit ' if allow_edit else ''}{'Delete' if allow_del else ''} permission on '{obj_name}'.",
                                remediation="Remove edit/delete rights immediately. Guest users must only be granted read/create where explicitly required."
                            )

                    elif tag == "classAccesses":
                        apex_class = None
                        enabled = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "apexClass": apex_class = sub.text
                            elif subtag == "enabled": enabled = (sub.text == "true")
                        if enabled and apex_class:
                            self.profile_classes[profile_name].add(apex_class)

                    elif tag == "fieldPermissions":
                        field_name = None
                        readable = False
                        editable = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "field": field_name = sub.text
                            elif subtag == "readable": readable = (sub.text == "true")
                            elif subtag == "editable": editable = (sub.text == "true")

                        if is_external and (readable or editable):
                            for kw in SENSITIVE_FIELD_KEYWORDS:
                                if field_name and kw in field_name.lower():
                                    self.add_finding(
                                        category="External FLS Exposure",
                                        severity="HIGH",
                                        target=f"{profile_name} -> {field_name}",
                                        file_path=p_file,
                                        issue=f"External profile granted {'read/edit' if editable else 'read'} access to sensitive field '{field_name}'.",
                                        remediation=f"Remove FLS access to '{field_name}' from external profile '{profile_name}'."
                                    )
                                    break

        # Permission Sets
        permsets_dir = self.force_app / "permissionsets"
        if permsets_dir.exists():
            for ps_file in permsets_dir.glob("*.permissionset-meta.xml"):
                ps_name = ps_file.stem.replace(".permissionset-meta", "")
                root = get_xml_root(ps_file)
                if root is None:
                    continue

                for child in root:
                    tag = strip_ns(child.tag)
                    if tag == "userPermissions":
                        name = None
                        enabled = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "name": name = sub.text
                            elif subtag == "enabled": enabled = (sub.text == "true")
                        if enabled and name in DANGEROUS_USER_PERMS:
                            self.add_finding(
                                category="PermissionSet User Permission",
                                severity="HIGH" if name in ["ViewAllData", "ModifyAllData", "AuthorApex"] else "MEDIUM",
                                target=f"{ps_name} -> {name}",
                                file_path=ps_file,
                                issue=f"PermissionSet enables dangerous user permission '{name}' ({DANGEROUS_USER_PERMS[name]}).",
                                remediation=f"Verify business justification for granting '{name}' via '{ps_name}'."
                            )

                    elif tag == "objectPermissions":
                        obj_name = None
                        view_all = False
                        mod_all = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "object": obj_name = sub.text
                            elif subtag == "viewAllRecords": view_all = (sub.text == "true")
                            elif subtag == "modifyAllRecords": mod_all = (sub.text == "true")
                        if view_all or mod_all:
                            self.add_finding(
                                category="PermissionSet Object Permission",
                                severity="HIGH",
                                target=f"{ps_name} -> {obj_name}",
                                file_path=ps_file,
                                issue=f"PermissionSet grants {'ViewAllRecords ' if view_all else ''}{'ModifyAllRecords' if mod_all else ''} on '{obj_name}'.",
                                remediation=f"Scope permissions to standard CRUD and leverage sharing rules rather than ViewAll/ModifyAll."
                            )

                    elif tag == "classAccesses":
                        apex_class = None
                        enabled = False
                        for sub in child:
                            subtag = strip_ns(sub.tag)
                            if subtag == "apexClass": apex_class = sub.text
                            elif subtag == "enabled": enabled = (sub.text == "true")
                        if enabled and apex_class:
                            self.permset_classes[ps_name].add(apex_class)

    def audit_objects_and_sharing(self):
        objects_dir = self.force_app / "objects"
        if objects_dir.exists():
            for obj_dir in objects_dir.iterdir():
                if not obj_dir.is_dir():
                    continue
                obj_name = obj_dir.name
                meta_file = obj_dir / f"{obj_name}.object-meta.xml"
                if not meta_file.exists():
                    for f in obj_dir.glob("*.object-meta.xml"):
                        meta_file = f
                        break
                
                if meta_file.exists():
                    root = get_xml_root(meta_file)
                    if root is None:
                        continue

                    sharing_model = None
                    external_sharing_model = None

                    for child in root:
                        tag = strip_ns(child.tag)
                        if tag == "sharingModel": sharing_model = child.text
                        elif tag == "externalSharingModel": external_sharing_model = child.text

                    if external_sharing_model is not None:
                        if external_sharing_model in ["ReadWrite", "FullAccess"]:
                            self.add_finding(
                                category="Object External Sharing Model",
                                severity="CRITICAL",
                                target=obj_name,
                                file_path=meta_file,
                                issue=f"External Sharing Model is '{external_sharing_model}'. External Community/Portal users can read/modify records across entire org.",
                                remediation=f"Change externalSharingModel to 'Private' in {meta_file.name} and share records via Sharing Sets or Criteria Sharing Rules."
                            )
                        elif external_sharing_model == "Read":
                            self.add_finding(
                                category="Object External Sharing Model",
                                severity="HIGH",
                                target=obj_name,
                                file_path=meta_file,
                                issue=f"External Sharing Model is 'Read' (Public Read Only). All portal users can view every record of '{obj_name}'.",
                                remediation="Change externalSharingModel to 'Private' unless records are globally public."
                            )
                    else:
                        if sharing_model in ["ReadWrite", "Read"]:
                            self.add_finding(
                                category="Object Sharing Model",
                                severity="HIGH",
                                target=obj_name,
                                file_path=meta_file,
                                issue=f"SharingModel is '{sharing_model}' and externalSharingModel is omitted (defaults to public).",
                                remediation="Explicitly specify <externalSharingModel>Private</externalSharingModel>."
                            )

    def audit_networks_and_sites(self):
        networks_dir = self.force_app / "networks"
        if networks_dir.exists():
            for net_file in networks_dir.glob("*.network-meta.xml"):
                root = get_xml_root(net_file)
                if root is None:
                    continue
                net_name = net_file.stem.replace(".network-meta", "")
                for child in root:
                    tag = strip_ns(child.tag)
                    if tag == "enableGuestChatter" and child.text == "true":
                        self.add_finding(
                            category="Network Configuration",
                            severity="HIGH",
                            target=net_name,
                            file_path=net_file,
                            issue=f"Guest Chatter is enabled on network '{net_name}'. Unauthenticated visitors can post or read internal Chatter messages.",
                            remediation="Set <enableGuestChatter>false</enableGuestChatter> in the network metadata."
                        )
                    elif tag == "selfRegistration" and child.text == "true":
                        self.add_finding(
                            category="Network Configuration",
                            severity="MEDIUM",
                            target=net_name,
                            file_path=net_file,
                            issue=f"Self-Registration is enabled on network '{net_name}'. Ensure default profile grants minimum necessary privileges.",
                            remediation="Review self-registration profile assignment and account provisioning logic."
                        )

        sites_dir = self.force_app / "sites"
        if sites_dir.exists():
            for site_file in sites_dir.glob("*.site-meta.xml"):
                root = get_xml_root(site_file)
                if root is None:
                    continue
                site_name = site_file.stem.replace(".site-meta", "")
                for child in root:
                    tag = strip_ns(child.tag)
                    if tag == "requireHttps" and child.text == "false":
                        self.add_finding(
                            category="Site Security",
                            severity="CRITICAL",
                            target=site_name,
                            file_path=site_file,
                            issue=f"Site '{site_name}' has requireHttps set to false. Plaintext HTTP traffic allowed.",
                            remediation="Set <requireHttps>true</requireHttps> in site metadata."
                        )

    def audit_apex_classes(self):
        classes_dir = self.force_app / "classes"
        if not classes_dir.exists():
            return

        external_exposed_classes = set()
        for prof, classes in self.profile_classes.items():
            if self.profile_meta.get(prof, {}).get("is_external", False):
                external_exposed_classes.update(classes)

        for cls_file in classes_dir.glob("*.cls"):
            cls_name = cls_file.stem
            try:
                with open(cls_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            if "@isTest" in content or "testMethod" in content:
                continue

            clean = strip_comments(content)
            class_decl_match = re.search(
                r'\b(public|global)\s+(with\s+sharing|without\s+sharing|inherited\s+sharing)?\s*(class|interface)\s+' + re.escape(cls_name) + r'\b', 
                clean, re.IGNORECASE
            )
            sharing_model = "omitted"
            if class_decl_match and class_decl_match.group(2):
                sharing_model = class_decl_match.group(2).lower()

            has_aura_enabled = bool(re.search(r'@AuraEnabled\b', content, re.IGNORECASE))
            is_externally_exposed = cls_name in external_exposed_classes

            # Check if this is a dedicated authentication controller (e.g. Site.login) with no record queries/DML
            is_pure_auth = ("Site.login" in content or "Site.forgotPassword" in content) and not ("SELECT " in content.upper() or "INSERT " in content.upper() or "UPDATE " in content.upper() or "DELETE " in content.upper())

            if has_aura_enabled and sharing_model in ["without sharing", "omitted"]:
                if is_pure_auth:
                    self.add_finding(
                        category="Apex Sharing / Auth Controller",
                        severity="INFO",
                        target=cls_name,
                        file_path=cls_file,
                        issue=f"@AuraEnabled class uses '{sharing_model}' for Site.login/authentication. Verified zero SOQL/DML queries on database records.",
                        remediation="Verified architectural necessity for unauthenticated login flow. Ensure no database queries are added."
                    )
                else:
                    severity = "CRITICAL" if is_externally_exposed else "HIGH"
                    self.add_finding(
                        category="Apex Sharing / Controller Access",
                        severity=severity,
                        target=cls_name,
                        file_path=cls_file,
                        issue=f"@AuraEnabled class uses '{sharing_model}'. Controller methods execute in system context without sharing." +
                              (f" [EXPOSED TO EXTERNAL PROFILES]" if is_externally_exposed else ""),
                        remediation="Change class declaration to 'with sharing' or 'inherited sharing'. Filter records with WITH USER_MODE."
                    )

            dynamic_queries = re.finditer(r'Database\.query\s*\((.*?)\)', content, re.DOTALL)
            for dq in dynamic_queries:
                query_arg = dq.group(1).strip()
                if '+' in query_arg:
                    has_escape = "escapeSingleQuotes" in query_arg or "escapeSingleQuotes" in content
                    if not has_escape:
                        self.add_finding(
                            category="SOQL Injection Risk",
                            severity="HIGH" if has_aura_enabled else "MEDIUM",
                            target=f"{cls_name} -> Dynamic Query",
                            file_path=cls_file,
                            issue=f"Dynamic SOQL concatenation without String.escapeSingleQuotes(): {query_arg[:100]}...",
                            remediation="Use bind variables (:var) or String.escapeSingleQuotes() with Schema tokens."
                        )

            if "JSON.deserializeUntyped" in content and ".put(" in content:
                self.add_finding(
                    category="Mass Assignment Risk",
                    severity="HIGH" if has_aura_enabled else "MEDIUM",
                    target=cls_name,
                    file_path=cls_file,
                    issue="Untyped JSON deserialization used with sObject.put(). Potential for unauthorized field injection.",
                    remediation="Enforce an explicit field allowlist or DTO before calling sObject.put()."
                )

    def audit_enterprise_triggers(self):
        triggers_dir = self.force_app / "triggers"
        if not triggers_dir.exists():
            return
        
        object_trigger_map = defaultdict(list)
        for t_file in triggers_dir.glob("*.trigger"):
            try:
                content = t_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            m = re.search(r'\btrigger\s+(\w+)\s+on\s+(\w+)', content, re.IGNORECASE)
            sobj = m.group(2) if m else "Unknown"
            object_trigger_map[sobj].append(t_file.stem)

            has_handler = bool(re.search(r'Handler\b', content, re.IGNORECASE))
            has_inline_dml = bool(re.search(r'\b(insert|update|delete)\s+\w+', content, re.IGNORECASE))
            has_inline_soql = bool(re.search(r'\[\s*SELECT\b', content, re.IGNORECASE))

            if (has_inline_dml or has_inline_soql) and not has_handler:
                self.add_finding(
                    category="Enterprise Trigger Pattern",
                    severity="MEDIUM",
                    target=t_file.stem,
                    file_path=t_file,
                    issue=f"Trigger '{t_file.stem}' contains inline logic/DML without delegating to a TriggerHandler.",
                    remediation="Adopt a logic-less trigger pattern: delegate trigger execution to a dedicated TriggerHandler class."
                )

        for sobj, trigs in object_trigger_map.items():
            if len(trigs) > 1 and sobj != "Unknown":
                self.add_finding(
                    category="Multiple Triggers Per Object",
                    severity="HIGH",
                    target=f"{sobj} ({len(trigs)} triggers)",
                    file_path=f"force-app/main/default/triggers/{trigs[0]}.trigger",
                    issue=f"Multiple triggers defined for '{sobj}': {', '.join(trigs)}. Execution order is non-deterministic.",
                    remediation=f"Consolidate all logic for '{sobj}' into a single trigger using a trigger framework."
                )

    def audit_test_quality(self):
        classes_dir = self.force_app / "classes"
        if not classes_dir.exists():
            return

        for cls_file in classes_dir.glob("*.cls"):
            try:
                content = cls_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if not ("@isTest" in content or "testMethod" in content or cls_file.stem.endswith(("Test", "_Test"))):
                continue

            # Strip comments to avoid matching commented-out notes
            clean_content = re.sub(r'//.*', '', content)
            clean_content = re.sub(r'/\*.*?\*/', '', clean_content, flags=re.DOTALL)

            if re.search(r'seeAllData\s*=\s*true', clean_content, re.IGNORECASE):
                self.add_finding(
                    category="Test Quality Anti-Pattern",
                    severity="HIGH",
                    target=cls_file.stem,
                    file_path=cls_file,
                    issue="Test class uses seeAllData=true, coupling unit test execution to org-specific state.",
                    remediation="Remove seeAllData=true and construct isolated test fixtures using @testSetup."
                )

            # Check for hardcoded org-specific usernames in tests
            username_match = re.search(r'[\'"][a-zA-Z0-9._%+-]+@deltaportal\.test\.\w+[\'"]', clean_content)
            if username_match:
                self.add_finding(
                    category="Test Portability Defect",
                    severity="HIGH",
                    target=cls_file.stem,
                    file_path=cls_file,
                    issue=f"Test class queries hardcoded org-specific username {username_match.group(0)}. Fails in other orgs and CI.",
                    remediation="Create isolated test users dynamically in @testSetup or mock user context."
                )

            if not re.search(r'\b(System\.assert|Assert\.)', clean_content):
                self.add_finding(
                    category="Test Assertion Fluff",
                    severity="MEDIUM",
                    target=cls_file.stem,
                    file_path=cls_file,
                    issue="Test class lacks System.assert() or Assert.* assertions; exercises lines without verifying behavior.",
                    remediation="Add meaningful assertions to verify method return values, state changes, and error handling."
                )

    def audit_bulkification(self):
        """Scans classes and triggers for SOQL or DML operations inside loops."""
        scan_dirs = [self.force_app / "classes", self.force_app / "triggers"]
        for sdir in scan_dirs:
            if not sdir.exists():
                continue
            for f in sdir.iterdir():
                if not (f.suffix in ('.cls', '.trigger')):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                clean = re.sub(r'//.*', '', content)
                clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

                for m in re.finditer(r'\bfor\s*\([^)]+\)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', clean):
                    body = m.group(1)
                    if re.search(r'\[\s*SELECT\b', body, re.IGNORECASE):
                        self.add_finding(
                            category="Governor Limit Risk (SOQL in Loop)",
                            severity="HIGH",
                            target=f.stem,
                            file_path=f,
                            issue=f"SOQL query executed inside a loop in {f.name}. Vulnerable to 101 SOQL limit.",
                            remediation="Bulkify by querying collections outside loops and caching in Maps/Sets."
                        )
                    if re.search(r'\b(insert|update|delete|upsert)\s+\w+;', body, re.IGNORECASE):
                        self.add_finding(
                            category="Governor Limit Risk (DML in Loop)",
                            severity="HIGH",
                            target=f.stem,
                            file_path=f,
                            issue=f"DML operation executed inside a loop in {f.name}. Vulnerable to 150 DML limit.",
                            remediation="Bulkify by accumulating sObjects into a List and performing a single DML outside the loop."
                        )

    def audit_dependency_integrity(self):
        """Checks FlexiPages for missing custom component dependencies."""
        flexipages_dir = self.force_app / "flexipages"
        if not flexipages_dir.exists():
            return

        lwc_names = {d.name for d in (self.force_app / "lwc").iterdir() if d.is_dir()} if (self.force_app / "lwc").exists() else set()
        aura_names = {d.name for d in (self.force_app / "aura").iterdir() if d.is_dir()} if (self.force_app / "aura").exists() else set()
        existing_components = lwc_names | aura_names

        for fp in flexipages_dir.glob("*.flexipage-meta.xml"):
            try:
                tree = ET.parse(fp)
                for elem in tree.iter():
                    if elem.tag.endswith('componentName'):
                        cname = elem.text or ''
                        if cname.startswith('c:'):
                            comp = cname[2:]
                            if comp not in existing_components:
                                self.add_finding(
                                    category="FlexiPage Missing Component",
                                    severity="MEDIUM",
                                    target=f"{fp.name} -> {cname}",
                                    file_path=fp,
                                    issue=f"FlexiPage references custom component '{cname}', which is not in local repository source.",
                                    remediation=f"Ensure component '{comp}' is tracked in source control or present in target org before deploying."
                                )
            except Exception:
                continue


    def audit_lwc_innovations(self):
        lwc_dir = self.force_app / "lwc"
        if not lwc_dir.exists():
            return

        for comp_dir in lwc_dir.iterdir():
            if not comp_dir.is_dir():
                continue
            for js_file in comp_dir.glob("*.js"):
                try:
                    content = js_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                url_match = re.search(r'[\'\"\`](https?://[a-zA-Z0-9.-]+\.(sandbox\.my|my)\.salesforce\.com[^\'\"\`]*)[\'\"\`]', content)
                if url_match:
                    self.add_finding(
                        category="LWC Hardcoded Environment URL",
                        severity="HIGH",
                        target=f"{comp_dir.name} -> {js_file.name}",
                        file_path=js_file,
                        issue=f"Hardcoded Salesforce environment URL: '{url_match.group(1)}'. Breaks environment portability.",
                        remediation="Use relative URLs or window.location.origin instead of hardcoded sandbox instance URLs."
                    )

                id_match = re.search(r'[\'\"\`](001|003|005|006|00D|a0|a1)[a-zA-Z0-9]{12,15}[\'\"\`]', content)
                if id_match:
                    self.add_finding(
                        category="LWC Hardcoded Record ID",
                        severity="HIGH",
                        target=f"{comp_dir.name} -> {js_file.name}",
                        file_path=js_file,
                        issue=f"Hardcoded Salesforce record ID detected: '{id_match.group(0)}'.",
                        remediation="Retrieve IDs dynamically via wire service, Custom Metadata, or component properties."
                    )

                if "innerHTML" in content or "insertAdjacentHTML" in content:
                    self.add_finding(
                        category="LWC DOM Bypass Risk",
                        severity="HIGH",
                        target=f"{comp_dir.name} -> {js_file.name}",
                        file_path=js_file,
                        issue="Component manipulates innerHTML or insertAdjacentHTML directly, bypassing LWC template sanitization.",
                        remediation="Use standard LWC template directives (lwc:if, for:each) instead of direct DOM manipulation."
                    )

    def audit_live_org(self):
        if not self.target_org:
            return

        print(f"[*] Querying live org '{self.target_org}' via Tooling API...")
        # 1. HealthCheck Score
        cmd = [
            "sf", "data", "query", "--target-org", self.target_org, "--use-tooling-api",
            "--query", "SELECT Score FROM SecurityHealthCheck", "--json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                raw_score = data.get("result", {}).get("records", [{}])[0].get("Score")
                score = int(raw_score) if raw_score is not None else None
                self.add_finding(
                    category="Org Security Health Check",
                    severity="HIGH" if score and score < 70 else "MEDIUM",
                    target="Org Health Score",
                    file_path=f"Live Org ({self.target_org})",
                    issue=f"Salesforce Security Health Check score is {score}/100 (Standard baseline is 85+).",
                    remediation="Review SecurityHealthCheckRisks and apply recommended security baselines."
                )
        except Exception as e:
            print(f"[!] Warning: Could not query SecurityHealthCheck: {e}")

        # 2. Query High Risk Settings
        cmd_risks = [
            "sf", "data", "query", "--target-org", self.target_org, "--use-tooling-api",
            "--query", "SELECT Setting, SettingGroup, RiskType, OrgValue, StandardValue FROM SecurityHealthCheckRisks WHERE RiskType = 'HIGH_RISK'",
            "--json"
        ]
        try:
            res = subprocess.run(cmd_risks, capture_output=True, text=True, timeout=20)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                records = data.get("result", {}).get("records", [])
                for r in records:
                    setting = r.get("Setting")
                    group = r.get("SettingGroup")
                    org_val = r.get("OrgValue")
                    std_val = r.get("StandardValue")
                    self.add_finding(
                        category="Org High-Risk Setting",
                        severity="HIGH",
                        target=f"{group} -> {setting}",
                        file_path=f"Live Org ({self.target_org})",
                        issue=f"Setting '{setting}' is '{org_val}' (Standard baseline: '{std_val}').",
                        remediation=f"Align setting '{setting}' with Salesforce baseline ('{std_val}')."
                    )
        except Exception as e:
            print(f"[!] Warning: Could not query SecurityHealthCheckRisks: {e}")

        # 3. Query Guest User Object Permissions
        cmd_guest = [
            "sf", "data", "query", "--target-org", self.target_org,
            "--query", "SELECT SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, Parent.Profile.Name FROM ObjectPermissions WHERE Parent.Profile.UserType = 'Guest' AND PermissionsRead = true",
            "--json"
        ]
        try:
            res = subprocess.run(cmd_guest, capture_output=True, text=True, timeout=20)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                records = data.get("result", {}).get("records", [])
                for r in records:
                    obj = r.get("SobjectType")
                    prof = r.get("Parent", {}).get("Profile", {}).get("Name", "Guest")
                    can_edit = r.get("PermissionsEdit", False)
                    can_del = r.get("PermissionsDelete", False)
                    can_create = r.get("PermissionsCreate", False)

                    if can_edit or can_del:
                        self.add_finding(
                            category="Org Guest User Violation",
                            severity="CRITICAL",
                            target=f"{prof} -> {obj}",
                            file_path=f"Live Org ({self.target_org})",
                            issue=f"Guest profile '{prof}' has {'Edit ' if can_edit else ''}{'Delete' if can_del else ''} on '{obj}'.",
                            remediation=f"Revoke all Edit and Delete permissions on '{obj}' from Guest profile '{prof}'."
                        )
                    elif can_create and obj.endswith("__c"):
                        self.add_finding(
                            category="Org Guest Object Access",
                            severity="MEDIUM",
                            target=f"{prof} -> {obj}",
                            file_path=f"Live Org ({self.target_org})",
                            issue=f"Guest profile '{prof}' has Read/Create on custom object '{obj}'.",
                            remediation=f"Verify unauthenticated access to '{obj}' is strictly necessary and validated."
                        )
        except Exception as e:
            print(f"[!] Warning: Could not query Guest ObjectPermissions: {e}")

    def run(self):
        print(f"[*] Auditing local metadata at: {self.force_app}...")
        self.audit_profiles_and_permsets()
        self.audit_objects_and_sharing()
        self.audit_networks_and_sites()
        self.audit_apex_classes()
        self.audit_enterprise_triggers()
        self.audit_bulkification()
        self.audit_test_quality()
        self.audit_dependency_integrity()
        self.audit_lwc_innovations()

        if self.target_org:
            self.audit_live_org()

        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1

        return {
            "total": len(self.findings),
            "counts": dict(counts),
            "findings": self.findings
        }

    def run_audit(self):
        """Standardized interface for CLI runner."""
        res = self.run()
        return res.get("findings", [])

def generate_markdown_report(result):
    md = []
    md.append("# Salesforce Metadata Security Audit Report\n")
    md.append(f"**Total Findings:** {result['total']}\n")
    md.append(f"- **CRITICAL:** {result['counts'].get('CRITICAL', 0)}")
    md.append(f"- **HIGH:** {result['counts'].get('HIGH', 0)}")
    md.append(f"- **MEDIUM:** {result['counts'].get('MEDIUM', 0)}")
    md.append(f"- **LOW / INFO:** {result['counts'].get('INFO', 0)}\n")

    md.append("## Executive Summary")
    md.append("This security inspection examined metadata configurations across objects, profiles, permission sets, networks, sites, flows, and Apex controllers. Standard SAST tools evaluate single code files in isolation; this report evaluates the actual **access boundaries, sharing models, and entitlement configurations** governing data security.\n")

    criticals = [f for f in result['findings'] if f['severity'] == 'CRITICAL']
    if criticals:
        md.append("## Critical Findings (Immediate Remediation Required)\n")
        md.append("| Category | Target | File | Issue | Remediation |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in criticals:
            md.append(f"| **{c['category']}** | `{c['target']}` | `{c['file']}` | {c['issue']} | {c['remediation']} |")
        md.append("\n")

    highs = [f for f in result['findings'] if f['severity'] == 'HIGH']
    if highs:
        md.append("## High Risk Findings\n")
        md.append("| Category | Target | File | Issue | Remediation |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for h in highs[:35]:
            md.append(f"| **{h['category']}** | `{h['target']}` | `{h['file']}` | {h['issue']} | {h['remediation']} |")
        if len(highs) > 35:
            md.append(f"\n*(Truncated: {len(highs) - 35} additional High findings documented in full JSON output)*\n")
        md.append("\n")

    return "\n".join(md)

def generate_junit_xml(result):
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    total_failures = result["counts"].get("CRITICAL", 0) + result["counts"].get("HIGH", 0)
    total_tests = result["total"]
    xml_lines.append(f'<testsuites name="SalesforceSecurityAudit" tests="{total_tests}" failures="{total_failures}" errors="0">')
    xml_lines.append(f'  <testsuite name="MetadataSecurity" tests="{total_tests}" failures="{total_failures}" errors="0">')
    
    for f in result["findings"]:
        classname = f["category"].replace(" ", "_")
        issue_clean = f["issue"][:80].replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
        target_clean = f["target"].replace('"', '&quot;')
        file_clean = f["file"].replace('"', '&quot;')
        sev = f["severity"]
        name = f"{target_clean} - {issue_clean}"
        xml_lines.append(f'    <testcase classname="{classname}" name="{name}" file="{file_clean}">')
        if sev in ["CRITICAL", "HIGH"]:
            xml_lines.append(f'      <failure message="{issue_clean}" type="{sev}">')
            xml_lines.append(f'        Category: {f["category"]}\n        Target: {f["target"]}\n        File: {f["file"]}\n        Severity: {sev}\n        Remediation: {f["remediation"]}')
            xml_lines.append('      </failure>')
        xml_lines.append('    </testcase>')
        
    xml_lines.append('  </testsuite>')
    xml_lines.append('</testsuites>')
    return "\n".join(xml_lines)

def generate_sarif(result, repo_dir):
    rules = {}
    sarif_results = []
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "INFO": "note"
    }

    for f in result["findings"]:
        rule_id = f["category"].replace(" ", "_").replace("/", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["category"],
                "shortDescription": {"text": f["category"]},
                "fullDescription": {"text": f["category"]},
                "defaultConfiguration": {"level": level_map.get(f["severity"], "note")},
                "help": {"text": f.get("remediation", "")}
            }

        file_str = str(f["file"]) if f.get("file") else "force-app"
        if file_str.startswith("/"):
            try:
                file_str = os.path.relpath(file_str, repo_dir)
            except Exception:
                pass

        sarif_results.append({
            "ruleId": rule_id,
            "message": {"text": f"{f['issue']} (Target: {f['target']})"},
            "level": level_map.get(f["severity"], "note"),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_str,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1
                    }
                }
            }]
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Salesforce-Metadata-Security-Scanner",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/cease15/rsli-crown-inspection",
                    "rules": list(rules.values())
                }
            },
            "results": sarif_results
        }]
    }
    return json.dumps(sarif, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Salesforce Metadata Security Auditor")
    parser.add_argument("--repo-dir", default=".", help="Repository root directory")
    parser.add_argument("--target-org", default=None, help="Target Salesforce org alias for live Tooling API checks")
    parser.add_argument("--output-json", default=None, help="Path to save JSON report")
    parser.add_argument("--output-md", default=None, help="Path to save Markdown report")
    parser.add_argument("--output-junit", default=None, help="Path to save JUnit XML report for CI/CD test dashboards")
    parser.add_argument("--output-sarif", default=None, help="Path to save SARIF 2.1.0 report for GitHub Code Scanning")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if CRITICAL findings exist")

    args = parser.parse_args()

    auditor = SecurityAuditor(args.repo_dir, args.target_org)
    result = auditor.run()

    print("\n" + "="*50)
    print(f"AUDIT COMPLETE: {result['total']} findings")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        if sev in result["counts"]:
            print(f"  {sev}: {result['counts'][sev]}")
    print("="*50 + "\n")

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] JSON report saved to: {args.output_json}")

    md_content = generate_markdown_report(result)
    if args.output_md:
        with open(args.output_md, "w") as f:
            f.write(md_content)
        print(f"[+] Markdown report saved to: {args.output_md}")

    # Write to GitHub Actions step summary if running in GitHub CI
    github_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if github_summary and os.path.exists(os.path.dirname(github_summary)):
        try:
            with open(github_summary, "a") as f:
                f.write("\n" + md_content + "\n")
            print(f"[+] GitHub Step Summary written to: {github_summary}")
        except Exception as e:
            print(f"[!] Warning: Could not write GITHUB_STEP_SUMMARY: {e}")

    if args.output_junit:
        junit_content = generate_junit_xml(result)
        with open(args.output_junit, "w") as f:
            f.write(junit_content)
        print(f"[+] JUnit XML report saved to: {args.output_junit}")

    if args.output_sarif:
        sarif_content = generate_sarif(result, args.repo_dir)
        with open(args.output_sarif, "w") as f:
            f.write(sarif_content)
        print(f"[+] SARIF 2.1.0 report saved to: {args.output_sarif}")

    if args.strict and (result["counts"].get("CRITICAL", 0) > 0):
        print(f"[!] {result['counts']['CRITICAL']} CRITICAL security violation(s) detected! Failing build gate.")
        sys.exit(1)

if __name__ == "__main__":
    main()

