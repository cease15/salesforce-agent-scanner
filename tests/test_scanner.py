import unittest
import tempfile
import os
from pathlib import Path

from sf_agent_scanner.metadata_security import SecurityAuditor
from sf_agent_scanner.apex_verifier import ApexVerifier
from sf_agent_scanner.lwc_verifier import LwcVerifier
from sf_agent_scanner.reporter import ScanReporter
from sf_agent_scanner.advisor import SpecialistAdvisor

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

    def test_aurahandledexception_missing_setmessage(self):
        apex_code = """
        public with sharing class CustomExceptionController {
            @AuraEnabled
            public static void failNow() {
                throw new AuraHandledException('Invalid ID');
            }
        }
        """
        cls_file = self.classes_dir / "CustomExceptionController.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        ahe_findings = [f for f in findings if f.get("rule_id") == "APEX-AURA-002"]
        self.assertTrue(len(ahe_findings) > 0)
        self.assertEqual(ahe_findings[0].get("severity"), "HIGH")

    def test_dml_in_cacheable_method(self):
        apex_code = """
        public with sharing class CacheableDmlController {
            @AuraEnabled(cacheable=true)
            public static void badUpdate(Account acc) {
                update acc;
            }
        }
        """
        cls_file = self.classes_dir / "CacheableDmlController.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        dml_findings = [f for f in findings if f.get("rule_id") == "APEX-AURA-CACHE-001"]
        self.assertTrue(len(dml_findings) > 0)
        self.assertEqual(dml_findings[0].get("severity"), "CRITICAL")

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

    def test_invocable_missing_description(self):
        apex_code = """
        public with sharing class InvocableActionNoDesc {
            @InvocableMethod(label='Execute Action')
            public static List<String> runAction(List<String> inputs) {
                return inputs;
            }
        }
        """
        cls_file = self.classes_dir / "InvocableActionNoDesc.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        invoc_findings = [f for f in findings if f.get("rule_id") == "AGENT-INVOC-001"]
        self.assertTrue(len(invoc_findings) > 0)
        self.assertEqual(invoc_findings[0].get("severity"), "HIGH")

    def test_invocable_multiple_methods(self):
        apex_code = """
        public with sharing class MultipleInvocablesClass {
            @InvocableMethod(label='Action One', description='Does thing one')
            public static List<String> actionOne(List<String> inputs) {
                return inputs;
            }
            @InvocableMethod(label='Action Two', description='Does thing two')
            public static List<String> actionTwo(List<String> inputs) {
                return inputs;
            }
        }
        """
        cls_file = self.classes_dir / "MultipleInvocablesClass.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        invoc2_findings = [f for f in findings if f.get("rule_id") == "AGENT-INVOC-002"]
        self.assertTrue(len(invoc2_findings) > 0)
        self.assertEqual(invoc2_findings[0].get("severity"), "CRITICAL")

    def test_service_layer_trigger_coupling(self):
        apex_code = """
        public with sharing class AccountService {
            public static void updateAccounts() {
                for (Account acc : (List<Account>)Trigger.new) {
                    acc.Rating = 'Hot';
                }
            }
        }
        """
        cls_file = self.classes_dir / "AccountService.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        service_findings = [f for f in findings if f.get("rule_id") == "APEX-ENTERPRISE-001"]
        self.assertTrue(len(service_findings) > 0)
        self.assertEqual(service_findings[0].get("severity"), "HIGH")

    def test_selector_missing_user_mode(self):
        apex_code = """
        public with sharing class OpportunitySelector {
            public static List<Opportunity> getOpenOpportunities() {
                return [SELECT Id, Name, Amount FROM Opportunity WHERE StageName != 'Closed Won'];
            }
        }
        """
        cls_file = self.classes_dir / "OpportunitySelector.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        selector_findings = [f for f in findings if f.get("rule_id") == "APEX-SELECTOR-001"]
        self.assertTrue(len(selector_findings) > 0)
        self.assertEqual(selector_findings[0].get("severity"), "HIGH")

    def test_invocable_reserved_keyword(self):
        apex_code = """
        public with sharing class InvocableWithReservedVar {
            public class Request {
                @InvocableVariable(label='Model Info', description='Car model')
                public String model;
            }
            @InvocableMethod(label='Get Model', description='Retrieves model information')
            public static List<String> getModel(List<Request> reqs) {
                return new List<String>();
            }
        }
        """
        cls_file = self.classes_dir / "InvocableWithReservedVar.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        reserved_findings = [f for f in findings if f.get("rule_id") == "AGENT-INVOC-003"]
        self.assertTrue(len(reserved_findings) > 0)
        self.assertEqual(reserved_findings[0].get("severity"), "CRITICAL")

    def test_hardcoded_id_and_fluff_in_test_class(self):
        apex_code = """
        @isTest
        private class SampleFluffTest {
            @isTest
            static void testMethodA() {
                Id hardcodedAcc = '0013q00001bcXYZAA2';
                System.assert(true, 'Component is valid');
                Assert.isTrue(true);
            }
        }
        """
        cls_file = self.classes_dir / "SampleFluffTest.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        id_findings = [f for f in findings if f.get("rule_id") == "APEX-TEST-004"]
        fluff_findings = [f for f in findings if f.get("rule_id") == "APEX-TEST-008"]
        self.assertTrue(len(id_findings) > 0)
        self.assertTrue(len(fluff_findings) >= 2)
        self.assertEqual(id_findings[0].get("severity"), "HIGH")
        self.assertEqual(fluff_findings[0].get("severity"), "HIGH")

    def test_missing_test_setup_and_start_stop_boundary(self):
        apex_code = """
        @isTest
        private class RepetitiveDmlTest {
            @isTest static void testOne() {
                insert new Account(Name = 'A1');
                System.enqueueJob(new MockQueueable());
                Assert.areEqual(1, [SELECT count() FROM Account]);
            }
            @isTest static void testTwo() {
                insert new Account(Name = 'A2');
                Assert.areEqual(1, [SELECT count() FROM Account]);
            }
            @isTest static void testThree() {
                insert new Account(Name = 'A3');
                Assert.areEqual(1, [SELECT count() FROM Account]);
            }
        }
        """
        cls_file = self.classes_dir / "RepetitiveDmlTest.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        setup_findings = [f for f in findings if f.get("rule_id") == "APEX-TEST-006"]
        async_findings = [f for f in findings if f.get("rule_id") == "APEX-TEST-005"]
        self.assertTrue(len(setup_findings) > 0)
        self.assertTrue(len(async_findings) > 0)
        self.assertEqual(setup_findings[0].get("severity"), "MEDIUM")
        self.assertEqual(async_findings[0].get("severity"), "MEDIUM")

    def test_missing_runas_in_controller_test_and_mixed_dml(self):
        apex_code = """
        @isTest
        private class DeltaPortalControllerTest {
            @isTest static void testPortalMethod() {
                insert new Account(Name = 'Test Corp');
                insert new User(Username = 'guest@portal.test', Alias='gp');
                DeltaPortalController.doSomething();
            }
        }
        """
        cls_file = self.classes_dir / "DeltaPortalControllerTest.cls"
        cls_file.write_text(apex_code)

        verifier = ApexVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        runas_findings = [f for f in findings if f.get("rule_id") == "APEX-TEST-007"]
        mixed_findings = [f for f in findings if f.get("rule_id") == "APEX-DATA-002"]
        self.assertTrue(len(runas_findings) > 0)
        self.assertTrue(len(mixed_findings) > 0)
        self.assertEqual(runas_findings[0].get("severity"), "HIGH")
        self.assertEqual(mixed_findings[0].get("severity"), "HIGH")

    import unittest.mock
    @unittest.mock.patch("subprocess.run")
    def test_live_org_coverage_and_failures(self, mock_run):
        def fake_run(cmd, capture_output=True, text=True, timeout=30):
            class FakeRes:
                returncode = 0
            query = ""
            for i, arg in enumerate(cmd):
                if arg == "--query":
                    query = cmd[i+1]
                    break
            import json
            res = FakeRes()
            if "ApexCodeCoverageAggregate" in query:
                res.stdout = json.dumps({
                    "result": {
                        "records": [
                            {"ApexClassOrTrigger": {"Name": "CrownQRTrigger"}, "NumLinesCovered": 0, "NumLinesUncovered": 10},
                            {"ApexClassOrTrigger": {"Name": "DeltaService"}, "NumLinesCovered": 10, "NumLinesUncovered": 90}
                        ]
                    }
                })
            elif "ApexTestResult" in query:
                res.stdout = json.dumps({
                    "result": {
                        "records": [
                            {"ApexClass": {"Name": "BrokenTest"}, "MethodName": "testFailure", "Message": "DmlException: FIELD_CUSTOM_VALIDATION_EXCEPTION"}
                        ]
                    }
                })
            elif "ApexTestQueueItem" in query:
                res.stdout = json.dumps({
                    "result": {
                        "records": [
                            {"Id": "709000000000001", "Status": "Processing", "ApexClass": {"Name": "SuiteTest"}}
                        ]
                    }
                })
            else:
                res.stdout = "{}"
            return res

        mock_run.side_effect = fake_run

        verifier = ApexVerifier(repo_dir=self.root, target_org="test-scratch")
        findings = verifier.run_all()
        cov_findings = [f for f in findings if f.get("rule_id") == "APEX-COV-001"]
        low_cov = [f for f in findings if f.get("rule_id") == "APEX-COV-002"]
        fail_findings = [f for f in findings if f.get("rule_id") == "APEX-LIVE-001"]
        queue_findings = [f for f in findings if f.get("rule_id") == "APEX-LIVE-002"]

        self.assertTrue(len(cov_findings) > 0)
        self.assertTrue(len(low_cov) > 0)
        self.assertTrue(len(fail_findings) > 0)
        self.assertTrue(len(queue_findings) > 0)
        self.assertEqual(fail_findings[0].get("severity"), "CRITICAL")
        self.assertEqual(cov_findings[0].get("severity"), "CRITICAL")


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

    def test_getter_mutation_detection(self):
        js_code = """
        import { LightningElement } from 'lwc';
        export default class TestComp extends LightningElement {
            get formattedDate() { return '2026-01-01'; }
            handleUpdate() {
                this.formattedDate = '2026-02-02';
            }
        }
        """
        (self.lwc_dir / "testComp.js").write_text(js_code)
        (self.lwc_dir / "testComp.html").write_text("<template></template>")

        verifier = LwcVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        mutate_findings = [f for f in findings if f.get("rule_id") == "LWC-GETTER-MUTATE"]
        self.assertTrue(len(mutate_findings) > 0)
        self.assertEqual(mutate_findings[0].get("severity"), "CRITICAL")

    def test_missing_navigation_mixin_extension(self):
        js_code = """
        import { LightningElement } from 'lwc';
        import { NavigationMixin } from 'lightning/navigation';
        export default class TestComp extends LightningElement {
            handleNav() {
                this[NavigationMixin.Navigate]({ type: 'standard__namedPage' });
            }
        }
        """
        (self.lwc_dir / "testComp.js").write_text(js_code)
        (self.lwc_dir / "testComp.html").write_text("<template></template>")

        verifier = LwcVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        mixin_findings = [f for f in findings if f.get("rule_id") == "LWC-MIXIN-001"]
        self.assertTrue(len(mixin_findings) > 0)
        self.assertEqual(mixin_findings[0].get("severity"), "CRITICAL")

    def test_aura_framework_leak_detection(self):
        js_code = """
        import { LightningElement } from 'lwc';
        export default class TestComp extends LightningElement {
            fireEvent() {
                $A.get('e.force:refreshView').fire();
            }
        }
        """
        (self.lwc_dir / "testComp.js").write_text(js_code)
        (self.lwc_dir / "testComp.html").write_text("<template></template>")

        verifier = LwcVerifier(repo_dir=self.root)
        findings = verifier.run_all()
        aura_findings = [f for f in findings if f.get("rule_id") == "LWC-AURA-001"]
        self.assertTrue(len(aura_findings) > 0)
        self.assertEqual(aura_findings[0].get("severity"), "CRITICAL")


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


class TestSpecialistAdvisor(unittest.TestCase):
    def test_explain_valid_rule(self):
        explanation = SpecialistAdvisor.explain("APEX-AURA-002")
        self.assertIn("AuraHandledException Missing setMessage()", explanation)
        self.assertIn("RECOMMENDED REMEDIATION", explanation)

    def test_explain_invalid_rule(self):
        res = SpecialistAdvisor.explain("INVALID-RULE-999")
        self.assertIn("not recognized", res)

    def test_list_rules(self):
        rules = SpecialistAdvisor.list_rules()
        self.assertIn("APEX-BULK-001", rules)
        self.assertIn("LWC-DOM-001", rules)
        self.assertIn("LWC-GETTER-MUTATE", rules)
        self.assertIn("AGENT-INVOC-001", rules)
        self.assertIn("AGENT-INVOC-002", rules)
        self.assertIn("APEX-ENTERPRISE-001", rules)
        self.assertIn("APEX-SELECTOR-001", rules)
        self.assertIn("SFDX-OVERRIDE-001", rules)
        self.assertIn("SFDX-FLS-001", rules)
        self.assertIn("AGENT-INVOC-003", rules)
        self.assertIn("AGENT-BUNDLE-002", rules)
        self.assertIn("AGENT-BUNDLE-003", rules)
        self.assertIn("AGENT-SAFETY-001", rules)
        self.assertIn("FLOW-BULK-001", rules)
        self.assertIn("FLOW-FAULT-001", rules)
        self.assertIn("FLOW-TIMING-001", rules)


class TestMetadataSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.default_dir = self.root / "force-app" / "main" / "default"
        self.default_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dangling_action_override(self):
        obj_dir = self.default_dir / "objects" / "Quote__c"
        obj_dir.mkdir(parents=True)
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <actionOverrides>
        <actionName>New</actionName>
        <content>nonExistentLwcOverride</content>
        <type>LightningComponent</type>
    </actionOverrides>
</CustomObject>
"""
        (obj_dir / "Quote__c.object-meta.xml").write_text(xml_content)

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        override_findings = [f for f in findings if f.get("rule_id") == "SFDX-OVERRIDE-001"]
        self.assertTrue(len(override_findings) > 0)
        self.assertEqual(override_findings[0].get("severity"), "CRITICAL")

    def test_non_contiguous_field_permissions(self):
        profiles_dir = self.default_dir / "profiles"
        profiles_dir.mkdir(parents=True)
        profile_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Profile xmlns="http://soap.sforce.com/2006/04/metadata">
    <custom>true</custom>
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Active__c</field>
        <readable>true</readable>
    </fieldPermissions>
    <userPermissions>
        <enabled>true</enabled>
        <name>ApiEnabled</name>
    </userPermissions>
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Rating</field>
        <readable>true</readable>
    </fieldPermissions>
</Profile>
"""
        (profiles_dir / "SplitProfile.profile-meta.xml").write_text(profile_xml)

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        fls_findings = [f for f in findings if f.get("rule_id") == "SFDX-FLS-001"]
        self.assertTrue(len(fls_findings) > 0)
        self.assertEqual(fls_findings[0].get("severity"), "HIGH")

    def test_sfdx_outdated_api_version(self):
        sfdx_proj = self.root / "sfdx-project.json"
        sfdx_proj.write_text('{"sourceApiVersion": "45.0"}')

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        ver_findings = [f for f in findings if f.get("rule_id") == "SFDX-VERSION-001"]
        self.assertTrue(len(ver_findings) > 0)
        self.assertEqual(ver_findings[0].get("severity"), "MEDIUM")

    def test_agentforce_bundle_missing_logic(self):
        bundle_dir = self.default_dir / "aiAuthoringBundles" / "TestAgent"
        bundle_dir.mkdir(parents=True)
        agent_script = """
start_agent router:
    reasoning:
        actions:
            lookup: @actions.lookup_action
                target: "apex://NonExistentBackingClass"
"""
        (bundle_dir / "TestAgent.agent").write_text(agent_script)

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        bundle_findings = [f for f in findings if f.get("rule_id") == "AGENT-BUNDLE-001"]
        self.assertTrue(len(bundle_findings) > 0)
        self.assertEqual(bundle_findings[0].get("severity"), "HIGH")

    def test_agentforce_bundle_ordering_and_hooks(self):
        bundle_dir = self.default_dir / "aiAuthoringBundles" / "BadOrderAgent"
        bundle_dir.mkdir(parents=True)
        agent_script = """
config:
    developer_name: "test"
system:
    instructions: ->
        | Hello user
start_agent router:
    before_reasoning:
        instructions: ->
            set @variables.x = True
    reasoning:
        instructions: ->
            | Route message
"""
        (bundle_dir / "BadOrderAgent.agent").write_text(agent_script)

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        order_findings = [f for f in findings if f.get("rule_id") == "AGENT-BUNDLE-002"]
        hook_findings = [f for f in findings if f.get("rule_id") == "AGENT-BUNDLE-003"]
        safety_findings = [f for f in findings if f.get("rule_id") == "AGENT-SAFETY-001"]
        self.assertTrue(len(order_findings) > 0)
        self.assertTrue(len(hook_findings) > 0)
        self.assertTrue(len(safety_findings) > 0)

    def test_flow_bulk_and_fault_checks(self):
        flows_dir = self.default_dir / "flows"
        flows_dir.mkdir(parents=True)
        flow_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Flow xmlns="http://soap.sforce.com/2006/04/metadata">
    <triggerType>RecordAfterSave</triggerType>
    <recordUpdates>
        <name>Update_Triggering_Record</name>
        <inputReference>$Record</inputReference>
    </recordUpdates>
    <loops>
        <name>Loop_Accounts</name>
        <nextValueConnector>
            <targetReference>Create_Account_Task</targetReference>
        </nextValueConnector>
    </loops>
    <recordCreates>
        <name>Create_Account_Task</name>
        <connector>
            <targetReference>Loop_Accounts</targetReference>
        </connector>
    </recordCreates>
</Flow>
"""
        (flows_dir / "BadFlow.flow-meta.xml").write_text(flow_xml)

        auditor = SecurityAuditor(repo_dir=self.root)
        findings = auditor.run_audit()
        bulk_findings = [f for f in findings if f.get("rule_id") == "FLOW-BULK-001"]
        fault_findings = [f for f in findings if f.get("rule_id") == "FLOW-FAULT-001"]
        timing_findings = [f for f in findings if f.get("rule_id") == "FLOW-TIMING-001"]
        self.assertTrue(len(bulk_findings) > 0)
        self.assertTrue(len(fault_findings) > 0)
        self.assertTrue(len(timing_findings) > 0)
        self.assertEqual(bulk_findings[0].get("severity"), "CRITICAL")
        self.assertEqual(timing_findings[0].get("severity"), "HIGH")


if __name__ == "__main__":
    unittest.main()
