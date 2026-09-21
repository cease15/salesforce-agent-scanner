import unittest
import tempfile
import os
from pathlib import Path

from sf_agent_scanner.metadata_security import SecurityAuditor
from sf_agent_scanner.apex_verifier import ApexVerifier
from sf_agent_scanner.lwc_verifier import LwcVerifier
from sf_agent_scanner.reporter import ScanReporter

class TestApexVerifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.classes_dir = self.root / "force-app" / "main" / "default" / "classes"
        self.classes_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_soql_in_loop_detection(self):
        apex_code = """
        public with sharing class BadLoopClass {
            public void runLoop(List<Id> ids) {
                for (Id recordId : ids) {
                    Account acc = [SELECT Id, Name FROM Account WHERE Id = :recordId LIMIT 1];
                }
            }
        }
        """
        cls_file = self.classes_dir / "BadLoopClass.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        soql_findings = [f for f in findings if f.get("rule_id") == "APEX-BULK-001"]
        self.assertTrue(len(soql_findings) > 0)
        self.assertEqual(soql_findings[0].get("severity"), "CRITICAL")

    def test_sharing_missing_detection(self):
        apex_code = """
        public class MissingSharingController {
            @AuraEnabled
            public static void doSomething() {}
        }
        """
        cls_file = self.classes_dir / "MissingSharingController.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        sharing_findings = [f for f in findings if f.get("rule_id") == "APEX-SEC-001"]
        self.assertTrue(len(sharing_findings) > 0)
        self.assertEqual(sharing_findings[0].get("severity"), "CRITICAL")

    def test_clean_apex_class(self):
        apex_code = """
        public with sharing class CleanApexClass {
            public List<Account> getAccounts(Set<Id> ids) {
                return [SELECT Id, Name FROM Account WHERE Id IN :ids];
            }
        }
        """
        cls_file = self.classes_dir / "CleanApexClass.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        self.assertEqual(len(findings), 0)


class TestLwcVerifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.lwc_dir = self.root / "force-app" / "main" / "default" / "lwc" / "testComp"
        self.lwc_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_inner_html_injection_detection(self):
        js_code = """
        import { LightningElement } from 'lwc';
        export default class TestComp extends LightningElement {
            renderedCallback() {
                this.template.querySelector('div').innerHTML = '<p>' + this.data + '</p>';
            }
        }
        """
        html_code = "<template><div></div></template>"
        (self.lwc_dir / "testComp.js").write_text(js_code)
        (self.lwc_dir / "testComp.html").write_text(html_code)

        verifier = LwcVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        xss_findings = [f for f in findings if f.get("rule_id") == "LWC-DOM-001"]
        self.assertTrue(len(xss_findings) > 0)
        self.assertEqual(xss_findings[0].get("severity"), "HIGH")

    def test_hardcoded_navigation_detection(self):
        js_code = """
        import { LightningElement } from 'lwc';
        export default class TestComp extends LightningElement {
            handleClick() {
                window.location.href = '/lightning/r/Account/' + this.recordId + '/view';
            }
        }
        """
        html_code = "<template><button onclick={handleClick}>View</button></template>"
        (self.lwc_dir / "testComp.js").write_text(js_code)
        (self.lwc_dir / "testComp.html").write_text(html_code)

        verifier = LwcVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        nav_findings = [f for f in findings if f.get("rule_id") == "LWC-NAV-001"]
        self.assertTrue(len(nav_findings) > 0)
        self.assertEqual(nav_findings[0].get("severity"), "HIGH")


class TestReporter(unittest.TestCase):
    def test_sarif_and_junit_generation(self):
        dummy_findings = [
            {
                "rule_id": "APEX-SEC-001",
                "severity": "HIGH",
                "title": "Missing explicit sharing model",
                "file": "force-app/main/default/classes/Test.cls",
                "line": 2,
                "description": "Class must declare with sharing"
            }
        ]
        reporter = ScanReporter(dummy_findings)
        sarif = reporter.to_sarif()
        self.assertEqual(sarif.get("version"), "2.1.0")

        junit = reporter.to_junit()
        self.assertIn("<testsuite", junit)
        self.assertIn("APEX-SEC-001", junit)

        md = reporter.to_markdown_summary()
        self.assertIn("Salesforce Specialist Agent CI/CD Quality Gate", md)

if __name__ == "__main__":
    unittest.main()
