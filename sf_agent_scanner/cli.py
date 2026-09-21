#!/usr/bin/env python3
"""
Salesforce Agent Scanner CLI Entrypoint
======================================
Unified runner executing Metadata Security, Apex Specialist, and LWC Specialist checks.
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Support running directly or as installed package
try:
    from sf_agent_scanner.metadata_security import SecurityAuditor
    from sf_agent_scanner.apex_verifier import ApexVerifier
    from sf_agent_scanner.lwc_verifier import LwcVerifier
    from sf_agent_scanner.reporter import ScanReporter
except ImportError:
    from metadata_security import SecurityAuditor
    from apex_verifier import ApexVerifier
    from lwc_verifier import LwcVerifier
    from reporter import ScanReporter

def main():
    parser = argparse.ArgumentParser(
        description="Universal Salesforce Specialist Agent Scanner & Quality Gate for CI/CD Pipelines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sf-agent-scan --all
  sf-agent-scan --apex --strict
  sf-agent-scan --lwc
  sf-agent-scan --security --sarif test-reports/security.sarif
  sf-agent-scan --all --target-org devtb --junit test-reports/junit.xml --summary-md step-summary.md
        """
    )
    parser.add_argument("--repo-dir", default=".", help="Root directory of the Salesforce repository (default: .)")
    parser.add_argument("--scope", choices=["all", "apex", "lwc", "security"], default="all", help="Scan scope to execute (default: all)")
    parser.add_argument("--apex", action="store_true", help="Run Apex specialist verification")
    parser.add_argument("--lwc", action="store_true", help="Run LWC specialist verification")
    parser.add_argument("--security", action="store_true", help="Run metadata security and governance audit")
    parser.add_argument("--all", action="store_true", help="Run all specialist verification gates (default)")
    parser.add_argument("--target-org", default="", help="Optional Salesforce target org alias for live Tooling API coverage checks")
    parser.add_argument("--strict", action="store_true", default=True, help="Enforce failure (exit code 1) on critical/high findings (default: true)")
    parser.add_argument("--no-strict", dest="strict", action="store_false", help="Do not exit with error code on findings (warning only)")
    parser.add_argument("--sarif", help="File path to write SARIF 2.1.0 report")
    parser.add_argument("--junit", help="File path to write JUnit XML test report")
    parser.add_argument("--json", action="store_true", help="Output all findings as JSON to stdout")
    parser.add_argument("--summary-md", help="File path to write Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--ado", action="store_true", help="Emit Azure DevOps pipeline logging commands")
    args = parser.parse_args()

    # Determine execution scope
    run_all = args.all or (not args.apex and not args.lwc and not args.security and args.scope == "all")
    run_apex = run_all or args.apex or args.scope == "apex"
    run_lwc = run_all or args.lwc or args.scope == "lwc"
    run_sec = run_all or args.security or args.scope == "security"

    repo_dir = Path(args.repo_dir).resolve()

    if not args.json:
        print("\n" + "="*70)
        print("      SALESFORCE SPECIALIST AGENT CI/CD PIPELINE SCANNER        ")
        print("="*70)
        print(f"Target Repository: {repo_dir}")
        print(f"Execution Scope:   Security={run_sec} | Apex={run_apex} | LWC={run_lwc}")
        if args.target_org:
            print(f"Target Org:        {args.target_org}")
        print("="*70 + "\n")

    all_findings = []

    # 1. Metadata Security Audit
    if run_sec:
        if not args.json:
            print("[*] [1/3] Running Metadata Security & Governance Auditor...")
        sec_auditor = SecurityAuditor(repo_dir=repo_dir, target_org=args.target_org or None)
        sec_findings = sec_auditor.run_audit()
        for f in sec_findings:
            f["rule_id"] = f.get("rule_id", "SF-SEC-001")
        all_findings.extend(sec_findings)
        if not args.json:
            print(f"    Completed. Findings: {len(sec_findings)}\n")

    # 2. Apex Specialist Verification
    if run_apex:
        if not args.json:
            print("[*] [2/3] Running Apex Specialist Verification (/apex*)...")
        apex_verifier = ApexVerifier(repo_dir=repo_dir, target_org=args.target_org or None)
        apex_findings = apex_verifier.run_all()
        all_findings.extend(apex_findings)
        if not args.json:
            print(f"    Completed. Findings: {len(apex_findings)}\n")

    # 3. LWC Specialist Verification
    if run_lwc:
        if not args.json:
            print("[*] [3/3] Running LWC Specialist Verification (/lwc*)...")
        lwc_verifier = LwcVerifier(repo_dir=repo_dir)
        lwc_findings = lwc_verifier.run_all()
        all_findings.extend(lwc_findings)
        if not args.json:
            print(f"    Completed. Findings: {len(lwc_findings)}\n")

    reporter = ScanReporter(all_findings)

    # Exporters
    if args.sarif:
        sarif_path = Path(args.sarif)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        with open(sarif_path, "w", encoding="utf-8") as sf:
            json.dump(reporter.to_sarif(), sf, indent=2)
        if not args.json:
            print(f"[+] SARIF 2.1.0 written to: {sarif_path}")

    if args.junit:
        junit_path = Path(args.junit)
        junit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(junit_path, "w", encoding="utf-8") as jf:
            jf.write(reporter.to_junit())
        if not args.json:
            print(f"[+] JUnit XML written to: {junit_path}")

    crit_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    gate_passed = (crit_count == 0 and high_count == 0)

    if args.summary_md:
        sum_path = Path(args.summary_md)
        sum_path.parent.mkdir(parents=True, exist_ok=True)
        with open(sum_path, "w", encoding="utf-8") as mf:
            mf.write(reporter.to_markdown_summary(target_org=args.target_org, gate_passed=gate_passed))
        if not args.json:
            print(f"[+] Markdown summary written to: {sum_path}")

    if args.ado:
        for cmd in reporter.emit_ado_commands():
            print(cmd)

    if args.json:
        print(json.dumps(all_findings, indent=2))
        sys.exit(0 if not (args.strict and not gate_passed) else 1)

    # CLI Terminal Summary
    med_count = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    info_count = sum(1 for f in all_findings if f.get("severity") == "INFO")

    print("="*70)
    print("                    FINAL AUDIT SUMMARY                         ")
    print("="*70)
    print(f"Total Findings: {len(all_findings)}")
    print(f"  CRITICAL:     {crit_count}")
    print(f"  HIGH:         {high_count}")
    print(f"  MEDIUM:       {med_count}")
    print(f"  INFO:         {info_count}")
    print("="*70)

    if not gate_passed:
        print(f"\n[-] QUALITY GATE FAILED: {crit_count + high_count} critical/high violation(s) detected.")
        if args.strict:
            sys.exit(1)
        else:
            print("[!] Continuing (--no-strict enabled).")
            sys.exit(0)
    else:
        print("\n[+] ALL QUALITY GATES PASSED CLEAN: Zero blocking violations.")
        sys.exit(0)

if __name__ == "__main__":
    main()
