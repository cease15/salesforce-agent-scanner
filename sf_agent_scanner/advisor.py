"""
Specialist Knowledge Advisor & Rule Registry
============================================
Provides deep architectural guidance, root-cause diagnostics, and copy-ready
remediations for all Salesforce Specialist Agent verification rules.
"""

SPECIALIST_RULES = {
    # --------------------------------------------------------------------------
    # Apex Specialist Rules (/apex*)
    # --------------------------------------------------------------------------
    "APEX-TRIG-001": {
        "title": "Multiple Triggers on Single sObject",
        "category": "Trigger Architecture",
        "severity": "HIGH",
        "description": "More than one trigger is declared on the same sObject. Salesforce does not guarantee the order of execution between multiple triggers on the same object.",
        "impact": "Non-deterministic execution order leads to intermittent race conditions, recursive loop bugs, and inconsistent transactional state.",
        "bad_example": """// BAD: Two separate triggers on Account
trigger AccountTrigger1 on Account (before insert) { ... }
trigger AccountTrigger2 on Account (before insert) { ... }""",
        "good_example": """// GOOD: Single trigger delegating to a logic-less handler
trigger AccountTrigger on Account (before insert, after insert, before update, after update) {
    TriggerHandler.run(new AccountTriggerHandler());
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_triggers_best_mgmt.htm"
    },
    "APEX-TRIG-002": {
        "title": "Inline Logic in Trigger",
        "category": "Trigger Architecture",
        "severity": "HIGH",
        "description": "Trigger contains business logic, SOQL queries, or DML statements directly in the trigger body instead of delegating to a TriggerHandler class.",
        "impact": "Inline trigger code cannot be unit-tested in isolation, cannot be reused across flows, and prevents disabling logic during batch processing.",
        "bad_example": """trigger CaseTrigger on Case (before insert) {
    for (Case c : Trigger.new) {
        c.Priority = 'High'; // Business logic inline
    }
}""",
        "good_example": """trigger CaseTrigger on Case (before insert) {
    CaseTriggerHandler.handleBeforeInsert(Trigger.new);
}""",
        "reference": "https://github.com/kevinohara80/sfdc-trigger-framework"
    },
    "APEX-BULK-001": {
        "title": "SOQL Query Inside Loop",
        "category": "Governor Limits (Bulkification)",
        "severity": "CRITICAL",
        "description": "A SOQL query is executed inside a loop (for, while, do-while). This directly threatens the synchronous limit of 101 SOQL queries.",
        "impact": "Production crashes with System.LimitException: Too many SOQL queries: 101 when processing bulk uploads or multi-record batches.",
        "bad_example": """for (Contact c : contacts) {
    Account acc = [SELECT Id, Name FROM Account WHERE Id = :c.AccountId]; // 101 limit trap!
}""",
        "good_example": """Set<Id> accIds = new Set<Id>();
for (Contact c : contacts) {
    if (c.AccountId != null) accIds.add(c.AccountId);
}
Map<Id, Account> accMap = new Map<Id, Account>([SELECT Id, Name FROM Account WHERE Id IN :accIds]);""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_gov_limits.htm"
    },
    "APEX-BULK-002": {
        "title": "DML Statement Inside Loop",
        "category": "Governor Limits (Bulkification)",
        "severity": "CRITICAL",
        "description": "A DML operation (insert, update, delete, upsert, Database.insert) is executed inside a loop.",
        "impact": "Breaches the 150 DML statements limit, aborting transactions and causing rollback in production batch contexts.",
        "bad_example": """for (Case c : casesToClose) {
    c.Status = 'Closed';
    update c; // 150 DML limit trap!
}""",
        "good_example": """List<Case> toUpdate = new List<Case>();
for (Case c : casesToClose) {
    c.Status = 'Closed';
    toUpdate.add(c);
}
if (!toUpdate.isEmpty()) update toUpdate;""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_gov_limits.htm"
    },
    "APEX-SEC-001": {
        "title": "Controller Missing Explicit Sharing",
        "category": "Apex Security & Sharing Context",
        "severity": "CRITICAL",
        "description": "Class exposing @AuraEnabled or @RestResource endpoints is declared without 'with sharing' or 'inherited sharing'.",
        "impact": "Methods execute in system mode, granting external community users access to records across the entire org, bypassing Organization-Wide Defaults.",
        "bad_example": """public class PortalCaseController { // Omits sharing! Runs in system mode.
    @AuraEnabled
    public static List<Case> getCases() { return [SELECT Id, Subject FROM Case]; }
}""",
        "good_example": """public with sharing class PortalCaseController {
    @AuraEnabled(cacheable=true)
    public static List<Case> getCases() {
        return [SELECT Id, Subject FROM Case WITH SECURITY_ENFORCED];
    }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_keywords_sharing.htm"
    },
    "APEX-SEC-002": {
        "title": "Guest Authentication Controller Sharing Model",
        "category": "Apex Security & Sharing Context",
        "severity": "INFO",
        "description": "Controller uses 'without sharing' strictly for unauthenticated Site.login/Site.forgotPassword flows with zero record DML/SOQL.",
        "impact": "Architecturally verified necessity for guest authentication before a session exists.",
        "bad_example": "N/A",
        "good_example": """public without sharing class DeltaLoginController {
    @AuraEnabled
    public static String login(String username, String password, String startUrl) {
        ApexPages.PageReference lpage = Site.login(username, password, startUrl);
        return lpage != null ? lpage.getUrl() : null;
    }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_sites.htm"
    },
    "APEX-SEC-003": {
        "title": "Dynamic SOQL Injection Risk",
        "category": "SOQL Injection Defense",
        "severity": "HIGH",
        "description": "Dynamic SOQL query string concatenated using '+' without String.escapeSingleQuotes() or bind variables.",
        "impact": "Allows SOQL injection attacks where an attacker crafts input that alters the query structure and extracts unauthorized data.",
        "bad_example": """String q = 'SELECT Id FROM Case WHERE Status = \\'' + userInput + '\\'';
List<Case> res = Database.query(q); // Injection vulnerability!""",
        "good_example": """// Preferred: Use direct SOQL bind variable
List<Case> res = Database.query('SELECT Id FROM Case WHERE Status = :userInput');
// Or sanitize:
String safeInput = String.escapeSingleQuotes(userInput);
List<Case> res = Database.query('SELECT Id FROM Case WHERE Status = \\'' + safeInput + '\\'');""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/pages_security_tips_soql_injection.htm"
    },
    "APEX-AURA-002": {
        "title": "AuraHandledException Missing setMessage()",
        "category": "Exception Sanitization",
        "severity": "HIGH",
        "description": "new AuraHandledException(msg) is thrown without calling e.setMessage(msg).",
        "impact": "Salesforce security defaults strip the exception message, causing portal/LWC users to see a generic, useless 'Script-thrown exception' error.",
        "bad_example": """// BAD: User sees "Script-thrown exception"
throw new AuraHandledException('Account ID cannot be blank.');""",
        "good_example": """// GOOD: Explicitly calls setMessage
AuraHandledException e = new AuraHandledException('Account ID cannot be blank.');
e.setMessage('Account ID cannot be blank.');
throw e;""",
        "reference": "https://salesforce.stackexchange.com/questions/122612/aurahandledexception-does-not-show-custom-message"
    },
    "APEX-AURA-CACHE-001": {
        "title": "DML in Cacheable Method",
        "category": "Apex Runtime Integrity",
        "severity": "CRITICAL",
        "description": "An @AuraEnabled(cacheable=true) method executes a DML operation (insert, update, delete, upsert).",
        "impact": "Crashes at runtime with System.InvalidParameterValueException: DML currently not allowed. Cacheable methods must be read-only.",
        "bad_example": """@AuraEnabled(cacheable=true)
public static void updateRecord(Account acc) {
    update acc; // Hard crash at runtime!
}""",
        "good_example": """@AuraEnabled
public static void updateRecord(Account acc) { // Remove cacheable=true
    update acc;
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/apex-wire-method.html"
    },
    "APEX-ASYNC-001": {
        "title": "Non-Primitive Parameter in @future Method",
        "category": "Asynchronous Apex",
        "severity": "CRITICAL",
        "description": "A @future method declares an sObject or complex object parameter instead of primitive data types or collections of primitives.",
        "impact": "Fails compilation or runtime deserialization. @future methods only accept primitives, arrays of primitives, or collections of primitives.",
        "bad_example": """@future
public static void processAccounts(List<Account> accs) { ... } // Compiler error!""",
        "good_example": """@future
public static void processAccounts(List<Id> accountIds) { ... }
// Or better: use Queueable Apex for complex types
public class ProcessAccountsQueueable implements Queueable {
    private List<Account> accounts;
    public ProcessAccountsQueueable(List<Account> accs) { this.accounts = accs; }
    public void execute(QueueableContext ctx) { ... }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_invoking_future_methods.htm"
    },
    "APEX-TEST-001": {
        "title": "Test Uses SeeAllData=true",
        "category": "Test Quality & Portability",
        "severity": "HIGH",
        "description": "Test class or method specifies @isTest(SeeAllData=true).",
        "impact": "Couples tests to existing sandbox data. Tests fail unexpectedly when data is modified or when deployed to fresh scratch orgs/production.",
        "bad_example": """@isTest(SeeAllData=true)
private class MyTest { ... }""",
        "good_example": """@isTest
private class MyTest {
    @testSetup
    static void setupTestData() {
        // Build isolated test fixtures in memory
        Account acc = new Account(Name = 'Test Corp');
        insert acc;
    }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_seealldata_using.htm"
    },
    "APEX-TEST-002": {
        "title": "Hardcoded Sandbox Username in Test",
        "category": "Test Quality & Portability",
        "severity": "HIGH",
        "description": "Test class queries a hardcoded username containing sandbox suffixes like '.dev', '.uat', or '@company.com'.",
        "impact": "Test immediately fails when run in any other sandbox, scratch org, or production pipeline.",
        "bad_example": """User u = [SELECT Id FROM User WHERE Username = 'admin@rsli.com.devtb'];""",
        "good_example": """// Create mock test user dynamically
User u = TestDataFactory.createStandardUser('testuser@example.com.test');""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_data_access.htm"
    },
    "APEX-TEST-003": {
        "title": "Test Class Has Zero Assertions",
        "category": "Test Quality & Portability",
        "severity": "HIGH",
        "description": "Test class executes code without any System.assert, Assert.areEqual, or Assert.isTrue checks.",
        "impact": "False sense of test coverage. Lines are exercised without verifying business behavior, allowing regression bugs to reach production.",
        "bad_example": """@isTest static void testMethod1() {
    MyController.doWork(); // No assertions! "Fluff" coverage.
}""",
        "good_example": """@isTest static void testMethod1() {
    Test.startTest();
    String result = MyController.doWork();
    Test.stopTest();
    Assert.areEqual('SUCCESS', result, 'Expected work to complete successfully');
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_best_practices.htm"
    },
    "APEX-TEST-004": {
        "title": "Hardcoded Salesforce Record ID in Test",
        "category": "Test Quality & Portability",
        "severity": "HIGH",
        "description": "Test code contains hardcoded 15 or 18 character Salesforce record IDs (e.g. '001...', '003...', '012...').",
        "impact": "Record IDs are specific to a single org instance. Hardcoded IDs immediately fail when deployed to scratch orgs, CI pipelines, or alternative sandboxes.",
        "bad_example": """Id accId = '0013q00001bcXYZAA2'; // Non-portable record ID!
Id rTypeId = '012Po000000gKbrIAE'; // Fails across environments""",
        "good_example": """// Query schema or factory instead:
Id rTypeId = Schema.SObjectType.Quote_Request__c.getRecordTypeInfosByDeveloperName().get('Standard').getRecordTypeId();
Account acc = TestDataFactory.createAccount('Test Corp');""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_best_practices.htm"
    },
    "APEX-TEST-005": {
        "title": "Missing Test.startTest() / Test.stopTest() Boundary",
        "category": "Test Quality & Portability",
        "severity": "MEDIUM",
        "description": "Test method performs data modifications or executes asynchronous code without Test.startTest() and Test.stopTest() boundaries.",
        "impact": "Governor limits are not refreshed for the execution under test. Asynchronous logic (@future, Queueable, Batchable) will not execute synchronously, causing false assertion failures.",
        "bad_example": """@isTest static void testAsyncJob() {
    insert new Account(Name = 'Test');
    System.enqueueJob(new MyQueueable());
    // Fails because queueable executes asynchronously outside start/stop boundary
    System.assertEquals(1, [SELECT count() FROM Audit_Log__c]);
}""",
        "good_example": """@isTest static void testAsyncJob() {
    insert new Account(Name = 'Test');
    Test.startTest(); // Resets governor limits
    System.enqueueJob(new MyQueueable());
    Test.stopTest();  // Forces queueable completion
    Assert.areEqual(1, [SELECT count() FROM Audit_Log__c]);
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_tools_start_stop_test.htm"
    },
    "APEX-TEST-006": {
        "title": "Missing @testSetup Data Factory Pattern",
        "category": "Test Performance & Data Architecture",
        "severity": "MEDIUM",
        "description": "Test class contains 3 or more test methods with redundant DML data creation without defining a static @testSetup method.",
        "impact": "Significantly inflates test suite execution time and sandbox CPU limits by re-inserting identical test records on every test method instead of using cached checkpoint data.",
        "bad_example": """@isTest static void testA() { Account a = new Account(Name='A'); insert a; ... }
@isTest static void testB() { Account a = new Account(Name='A'); insert a; ... }
@isTest static void testC() { Account a = new Account(Name='A'); insert a; ... }""",
        "good_example": """@testSetup static void setup() {
    Account a = new Account(Name='A');
    insert a;
}
@isTest static void testA() { Account a = [SELECT Id FROM Account LIMIT 1]; ... }""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_testsetup_using.htm"
    },
    "APEX-TEST-007": {
        "title": "Persona Verification Missing System.runAs()",
        "category": "Test Security & Access Control",
        "severity": "HIGH",
        "description": "Controller or security-sensitive class is tested without executing under specific user personas using System.runAs().",
        "impact": "Tests execute with full System Administrator privileges by default, masking Field-Level Security (FLS), sharing rule, and external Community/Portal user permission defects.",
        "bad_example": """@isTest static void testPortalController() {
    // Runs as Admin in test context - fails to catch FLS or guest user lockdown bugs!
    DeltaQuoteController.getQuotes();
}""",
        "good_example": """@isTest static void testPortalController() {
    User portalUser = [SELECT Id FROM User WHERE Profile.Name = 'RSLI Customer Community' LIMIT 1];
    System.runAs(portalUser) {
        DeltaQuoteController.getQuotes();
    }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_tools_runas.htm"
    },
    "APEX-TEST-008": {
        "title": "Meaningless Assertion Fluff",
        "category": "Test Quality & Portability",
        "severity": "HIGH",
        "description": "Test method contains tautological assertions such as System.assert(true), System.assertEquals(1, 1), or Assert.isTrue(true).",
        "impact": "Deceives code quality metrics and assertion gates without actually validating system state, computation accuracy, or database mutations.",
        "bad_example": """System.assert(true, 'Component exists in org');
Assert.isTrue(true);
System.assertEquals(1, 1);""",
        "good_example": """Quote_Request__c qr = [SELECT Status__c FROM Quote_Request__c WHERE Id = :qrId];
Assert.areEqual('Submitted', qr.Status__c, 'Quote Request status must transition to Submitted');""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_best_practices.htm"
    },
    "APEX-DATA-001": {
        "title": "Test Query Dependency on Unseeded Data",
        "category": "Test Data Architecture",
        "severity": "HIGH",
        "description": "Test method executes SOQL queries for business records without creating them in @testSetup or mocking them first.",
        "impact": "Tests fail unpredictably in scratch orgs, CI/CD runners, and refreshed sandboxes where pre-existing records do not exist.",
        "bad_example": """@isTest static void testApproval() {
    // Fails in fresh org because this specific record does not exist
    Account a = [SELECT Id FROM Account WHERE Name = 'RSLI Main' LIMIT 1];
}""",
        "good_example": """@testSetup static void setup() {
    insert new Account(Name = 'RSLI Main');
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_testing_load_data.htm"
    },
    "APEX-DATA-002": {
        "title": "Mixed DML Setup/Non-Setup Hazard",
        "category": "Apex Runtime Integrity",
        "severity": "HIGH",
        "description": "Test setup performs DML on setup objects (User, Group, PermissionSet) and non-setup objects (Account, Quote) in the same transaction context.",
        "impact": "Throws unhandled MIXED_DML_OPERATION exception: DML operation on setup object is not permitted after you have updated a non-setup object.",
        "bad_example": """insert new Account(Name = 'Acme');
insert new User(Username = 'u@test.com', ...); // CRASH: MIXED_DML_OPERATION!""",
        "good_example": """insert new Account(Name = 'Acme');
System.runAs(new User(Id = UserInfo.getUserId())) {
    insert new User(Username = 'u@test.com', ...); // Isolated in separate DML context
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_dml_non_mix_sobjects.htm"
    },
    "APEX-LIVE-001": {
        "title": "Target Org Live Test Failure Detected",
        "category": "Live Org Verification",
        "severity": "CRITICAL",
        "description": "Tooling API query on ApexTestResult detected active failing test methods with unhandled exceptions in the target org.",
        "impact": "Broken test classes fail CI validation gates, block production deployments, and signal active runtime regressions.",
        "bad_example": """ApexTestResult: InforceRateController_Test.testGetInforceRates_NoAccess_Denied: System.DmlException: Insert failed. First exception on row 0; first error: INVALID_OR_NULL_FOR_RESTRICTED_PICKLIST""",
        "good_example": """Ensure all required picklist values, validation rule requirements, and object relationships are satisfied by test factories before assertion.""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_apextestresult.htm"
    },
    "APEX-LIVE-002": {
        "title": "Target Org Test Queue In-Flight Hazard",
        "category": "Live Org Verification",
        "severity": "MEDIUM",
        "description": "Tooling API query detected test runs currently queued or executing in the target org.",
        "impact": "Running concurrent test runs or deployments while org test queues are active produces lock contention and inaccurate code coverage numbers.",
        "bad_example": """ApexTestQueueItem: 5 items in 'Queued' or 'Processing' state.""",
        "good_example": """Wait for test queue items to complete or clear prior execution queue before running pipeline test gates.""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/tooling_api_objects_apextestqueueitem.htm"
    },

    # --------------------------------------------------------------------------
    # LWC Specialist Rules (/lwc*)
    # --------------------------------------------------------------------------
    "LWC-DOM-001": {
        "title": "DOM Sanitization Bypass (innerHTML/outerHTML)",
        "category": "DOM Sanitization & Security",
        "severity": "HIGH",
        "description": "Direct manipulation of DOM elements via innerHTML, outerHTML, or insertAdjacentHTML.",
        "impact": "Bypasses Lightning Locker / Lightning Web Security sanitization and creates Cross-Site Scripting (XSS) vulnerabilities.",
        "bad_example": """this.template.querySelector('.container').innerHTML = '<p>' + this.userInput + '</p>';""",
        "good_example": """<!-- In template: -->
<template lwc:if={hasContent}>
    <p>{userInput}</p>
</template>""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/security-lwsec-intro.html"
    },
    "LWC-REACT-001": {
        "title": "Mutation of Public @api Property",
        "category": "Reactivity & Immutability",
        "severity": "HIGH",
        "description": "Component code reassigns or mutates a property decorated with @api (this.publicProp = ...).",
        "impact": "Violates one-way data flow in LWC. Can cause infinite render loops or subtle state de-synchronization between parent and child.",
        "bad_example": """export default class ChildComp extends LightningElement {
    @api recordId;
    handleChange() {
        this.recordId = 'new-id'; // Mutating public prop directly!
    }
}""",
        "good_example": """export default class ChildComp extends LightningElement {
    @api recordId;
    _internalRecordId;
    
    handleChange() {
        // Dispatch event to parent instead:
        this.dispatchEvent(new CustomEvent('recordchange', { detail: { recordId: 'new-id' } }));
    }
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/reactivity-public.html"
    },
    "LWC-GETTER-MUTATE": {
        "title": "Assignment to Getter-Only Property",
        "category": "Runtime Exception",
        "severity": "CRITICAL",
        "description": "Code attempts to assign a value to a property that is defined as a getter without a corresponding setter (this.foo = ... where get foo() exists).",
        "impact": "Throws an unrecoverable TypeError: Cannot set property of #<Object> which has only a getter in strict mode (all LWC modules run in strict mode), breaking component rendering.",
        "bad_example": """get formattedDate() { return this._date; }
handleUpdate() {
    this.formattedDate = '2026-01-01'; // HARD CRASH TypeError!
}""",
        "good_example": """get formattedDate() { return this._date; }
set formattedDate(value) { this._date = value; } // Add setter if mutable
// Or assign to private backing variable:
handleUpdate() { this._date = '2026-01-01'; }""",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/get"
    },
    "LWC-REFRESH-001": {
        "title": "refreshApex Passed Data Instead of Wired Object",
        "category": "Data Service (LDS) Integrity",
        "severity": "HIGH",
        "description": "refreshApex() is passed this.records (the data property) instead of the complete wired object result.",
        "impact": "refreshApex silently fails to refresh data from Salesforce. Newly created or deleted records will not appear on screen.",
        "bad_example": """@wire(getCases) cases;
handleSave() {
    refreshApex(this.cases.data); // WRONG: refreshApex does nothing!
}""",
        "good_example": """_wiredCasesResult;
@wire(getCases)
wiredCases(result) {
    this._wiredCasesResult = result; // Store full result
    if (result.data) this.cases = result.data;
}
async handleSave() {
    await refreshApex(this._wiredCasesResult); // Pass entire result object
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/apex-result-caching.html"
    },
    "LWC-NAV-001": {
        "title": "Direct window.location Navigation",
        "category": "Navigation Architecture",
        "severity": "HIGH",
        "description": "Navigation performed via direct window.location assignment instead of lightning/navigation (NavigationMixin).",
        "impact": "Forces full browser window reload, destroys SPA application state, breaks Experience Cloud routing, and fails on Salesforce Mobile App.",
        "bad_example": """window.location.href = '/lightning/r/Account/' + this.recordId + '/view';""",
        "good_example": """import { NavigationMixin } from 'lightning/navigation';
export default class MyComp extends NavigationMixin(LightningElement) {
    handleNav() {
        this[NavigationMixin.Navigate]({
            type: 'standard__recordPage',
            attributes: { recordId: this.recordId, actionName: 'view' }
        });
    }
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/use-navigate.html"
    },
    "LWC-MIXIN-001": {
        "title": "Missing NavigationMixin Class Extension",
        "category": "Navigation Architecture",
        "severity": "CRITICAL",
        "description": "Component uses this[NavigationMixin.Navigate] or this[NavigationMixin.GenerateUrl] without extending NavigationMixin(LightningElement).",
        "impact": "Throws TypeError: this[NavigationMixin.Navigate] is not a function at runtime when user triggers navigation.",
        "bad_example": """import { NavigationMixin } from 'lightning/navigation';
export default class MyComp extends LightningElement { // Forgot NavigationMixin!
    handleClick() { this[NavigationMixin.Navigate]({ ... }); }
}""",
        "good_example": """import { NavigationMixin } from 'lightning/navigation';
export default class MyComp extends NavigationMixin(LightningElement) {
    handleClick() { this[NavigationMixin.Navigate]({ ... }); }
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/use-navigate.html"
    },
    "LWC-SSR-001": {
        "title": "LWR Server-Side Rendering (SSR) Browser Global Leak",
        "category": "Experience Cloud (LWR)",
        "severity": "HIGH",
        "description": "Direct reference to window, document, or localStorage in component class constructor or field initializers.",
        "impact": "Crashes LWR SSR compilation with 'ReferenceError: window is not defined' during server pre-rendering.",
        "bad_example": """export default class MyComp extends LightningElement {
    screenHeight = window.innerHeight; // Crashes in LWR SSR!
}""",
        "good_example": """export default class MyComp extends LightningElement {
    screenHeight;
    connectedCallback() {
        if (typeof window !== 'undefined') {
            this.screenHeight = window.innerHeight;
        }
    }
}""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/ssr-intro.html"
    },
    "LWC-AURA-001": {
        "title": "Aura Framework ($A) Leak in LWC",
        "category": "Modernization & Runtime Integrity",
        "severity": "CRITICAL",
        "description": "Reference to legacy Aura global '$A' detected in Lightning Web Component.",
        "impact": "$A is undefined in LWC, throwing an unhandled ReferenceError: $A is not defined at runtime.",
        "bad_example": """$A.get('e.force:refreshView').fire(); // Legacy Aura code in LWC!""",
        "good_example": """// Modern LWC equivalent:
import { notifyRecordUpdateAvailable } from 'lightning/uiRecordApi';
await notifyRecordUpdateAvailable([{ recordId: this.recordId }]);""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/migrate-aura.html"
    },
    "LWC-ENV-001": {
        "title": "Hardcoded Salesforce Environment URL",
        "category": "Environment Decoupling",
        "severity": "HIGH",
        "description": "Hardcoded sandbox or My Domain URL ('salesforce.com', 'sandbox.my.salesforce.com').",
        "impact": "Breaks cross-environment deployment. URLs pointing to Dev/UAT fail or leak test data when deployed to production.",
        "bad_example": """const endpoint = 'https://myorg--devtb.sandbox.my.salesforce.com/services/apexrest/data';""",
        "good_example": """import basePath from '@salesforce/community/basePath';
const endpoint = `${basePath}/services/apexrest/data`;""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/get-base-path.html"
    },
    "LWC-ENV-002": {
        "title": "Hardcoded Salesforce Record ID",
        "category": "Environment Decoupling",
        "severity": "HIGH",
        "description": "Hardcoded 15-character or 18-character Salesforce record ID detected in JavaScript controller.",
        "impact": "Record IDs are org-specific. Hardcoded IDs will not exist in other sandboxes or production, resulting in 'Entity not found' errors.",
        "bad_example": """const DEFAULT_ACCOUNT_ID = '0015000000XyZ12345';""",
        "good_example": """@api recordId; // Pass dynamically
// Or query from Custom Metadata:
import getSetting from '@salesforce/apex/AppConfig.getDefaultId';""",
        "reference": "https://developer.salesforce.com/docs/platform/lwc/guide/reactivity-public.html"
    },
    "LWC-A11Y-001": {
        "title": "Interactive Element Missing Accessible Label",
        "category": "Accessibility (WCAG 2.1 AA)",
        "severity": "HIGH",
        "description": "Interactive element (button, input, icon-only button) lacks accessible text, aria-label, or title.",
        "impact": "Violates WCAG 2.1 AA compliance. Screen reader users cannot identify the function or purpose of the button.",
        "bad_example": """<button onclick={handleDelete} class="btn-icon">
    <lightning-icon icon-name="utility:delete"></lightning-icon>
</button>""",
        "good_example": """<button onclick={handleDelete} class="btn-icon" aria-label="Delete Quote Request" title="Delete Quote Request">
    <lightning-icon icon-name="utility:delete" alternative-text="Delete"></lightning-icon>
</button>""",
        "reference": "https://www.w3.org/WAI/WCAG21/Understanding/name-role-value.html"
    },
    "LWC-FORMULA-CSV": {
        "title": "CSV Formula Injection Risk",
        "category": "Application Security",
        "severity": "HIGH",
        "description": "CSV export code concatenates data without neutralizing spreadsheet formula execution prefixes (=, +, -, @).",
        "impact": "When exported CSV is opened in Excel, malicious cell contents starting with '=' execute arbitrary system commands or exfiltrate data.",
        "bad_example": """const csvContent = rows.map(r => r.name + ',' + r.value).join('\\n');""",
        "good_example": """function sanitizeCsvField(val) {
    if (typeof val === 'string' && /^[=\\+\\-@\\t\\r]/.test(val)) {
        return \"'\" + val; // Prepend apostrophe to neutralize formula
    }
    return val;
}""",
        "reference": "https://owasp.org/www-community/attacks/CSV_Injection"
    },

    # --------------------------------------------------------------------------
    # Agentforce & Atlas Reasoning Engine Rules
    # --------------------------------------------------------------------------
    "AGENT-INVOC-001": {
        "title": "Invocable Action Contract & Semantic Description",
        "category": "Agentforce Backing Logic",
        "severity": "HIGH",
        "description": "Apex @InvocableMethod backing an Agentforce action lacks a detailed description or does not follow bulkified List<Request>/List<Response> signature.",
        "impact": "The Atlas Reasoning Engine relies strictly on invocable method and variable descriptions to select actions and map utterance slots. Missing or low-quality descriptions cause the agent to hallucinate or fail action invocation.",
        "bad_example": """// BAD: Missing description, Atlas engine cannot infer action purpose
public class GetOrderAction {
    @InvocableMethod
    public static List<String> getOrder(List<String> orderNumbers) { ... }
}""",
        "good_example": """// GOOD: Explicit semantic descriptions for Atlas Reasoning Engine
public with sharing class GetOrderAction {
    public class Request {
        @InvocableVariable(label='Order Number' description='The 10-digit order tracking number (e.g. ORD-12345)' required=true)
        public String orderNumber;
    }
    public class Response {
        @InvocableVariable(label='Order Status' description='Current shipping status: Pending, Shipped, Delivered')
        public String status;
    }
    @InvocableMethod(label='Get Order Status' description='Retrieves shipping status, carrier, and delivery date for a customer order by order number.')
    public static List<Response> execute(List<Request> requests) { ... }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_annotation_InvocableMethod.htm"
    },
    "AGENT-INVOC-002": {
        "title": "Multiple Invocable Methods in Single Class",
        "category": "Agentforce Backing Logic",
        "severity": "CRITICAL",
        "description": "An Apex class declares more than one method with the @InvocableMethod annotation.",
        "impact": "Salesforce Apex compilation and deployment fails with error: 'Only one method per class can be annotated with InvocableMethod'. Actions cannot be resolved by Agentforce.",
        "bad_example": """public class OrderActions {
    @InvocableMethod(label='Get Order')
    public static List<Response> getOrder(List<Request> reqs) { ... }

    @InvocableMethod(label='Cancel Order') // Fails to compile!
    public static List<Response> cancelOrder(List<Request> reqs) { ... }
}""",
        "good_example": """// Split each invocable action into its own dedicated Apex class
public class GetOrderAction {
    @InvocableMethod(label='Get Order', description='Retrieves order status by ID.')
    public static List<Response> execute(List<Request> reqs) { ... }
}
public class CancelOrderAction {
    @InvocableMethod(label='Cancel Order', description='Cancels an existing order by ID.')
    public static List<Response> execute(List<Request> reqs) { ... }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_annotation_InvocableMethod.htm"
    },
    "AGENT-BUNDLE-001": {
        "title": "Agentforce Bundle Backing Logic Disconnected",
        "category": "Agentforce Script Integrity",
        "severity": "HIGH",
        "description": "An AiAuthoringBundle (.agent file) references backing logic (e.g. apex://ClassName) that does not exist in the repository.",
        "impact": "Agent Script validation or preview fails with unresolved action targets, preventing agent deployment and execution.",
        "bad_example": """actions:
    check_status: @actions.get_status
        target: "apex://NonExistentOrderService" # Missing class in force-app/main/default/classes/""",
        "good_example": """actions:
    check_status: @actions.get_status
        target: "apex://OrderServiceAction" # Class exists and compiles with @InvocableMethod""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.agentforce.meta/agentforce/agent_script_overview.htm"
    },

    # --------------------------------------------------------------------------
    # Salesforce Enterprise Design Patterns
    # --------------------------------------------------------------------------
    "APEX-ENTERPRISE-001": {
        "title": "Service Layer UI/Trigger Context Coupling",
        "category": "Enterprise Architecture (SoC)",
        "severity": "HIGH",
        "description": "A Service Layer class (*Service.cls) directly references Trigger context variables (Trigger.new, Trigger.old) or UI context (ApexPages).",
        "impact": "Violates Separation of Concerns (SoC). Coupled service methods cannot be invoked from REST APIs, asynchronous queueables, or Agentforce actions without mocking triggers.",
        "bad_example": """public class AccountService {
    public static void applyDiscount() {
        for (Account a : (List<Account>)Trigger.new) { // Coupled to Trigger context!
            a.Discount__c = 10;
        }
    }
}""",
        "good_example": """public with sharing class AccountService {
    // Pure service method accepts generic collection, callable from Triggers, APIs, or Agentforce
    public static void applyDiscount(List<Account> accounts) {
        for (Account a : accounts) {
            a.Discount__c = 10;
        }
        update accounts;
    }
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_service_layer.htm"
    },
    "APEX-SELECTOR-001": {
        "title": "SOQL Query Missing Security/User Mode",
        "category": "Selector & Security Pattern",
        "severity": "HIGH",
        "description": "A SOQL query in an Apex class does not enforce security mode via WITH USER_MODE or WITH SECURITY_ENFORCED.",
        "impact": "Queries execute in system mode, potentially returning fields and records the current user or external portal user has no permission to view.",
        "bad_example": """public List<Account> getActiveAccounts() {
    return [SELECT Id, Name, SSN__c FROM Account]; // System mode, ignores FLS!
}""",
        "good_example": """public List<Account> getActiveAccounts() {
    return [SELECT Id, Name, SSN__c FROM Account WITH USER_MODE]; // Enforces FLS & CRUD!
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_with_user_mode.htm"
    },

    # --------------------------------------------------------------------------
    # Salesforce DX & Metadata Discipline
    # --------------------------------------------------------------------------
    "SFDX-VERSION-001": {
        "title": "Outdated or Divergent API Version",
        "category": "Salesforce DX Discipline",
        "severity": "MEDIUM",
        "description": "Metadata component declares an apiVersion significantly lower than modern standard (>= 58.0, recommended 62.0+).",
        "impact": "Old API versions lack support for modern platform capabilities (LWS, Dynamic Forms, Assert class) and trigger false deploy rejections in CI pipelines.",
        "bad_example": """<apiVersion>45.0</apiVersion> <!-- Deprecated legacy version -->""",
        "good_example": """<apiVersion>62.0</apiVersion> <!-- Modern Winter '25 platform baseline -->""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.sfdx_dev.meta/sfdx_dev/sfdx_dev_source_file_format.htm"
    },
    "SFDX-OVERRIDE-001": {
        "title": "Dangling Action Override",
        "category": "Metadata Integrity",
        "severity": "CRITICAL",
        "description": "CustomObject action override references a LightningComponent or FlexiPage that does not exist in the source tree.",
        "impact": "Causes fatal deployment errors in scratch orgs and target pipelines (e.g. 'Component does not exist').",
        "bad_example": """<actionOverrides>
    <actionName>New</actionName>
    <content>deletedComponentOverride</content> <!-- Component deleted from repo! -->
    <type>LightningComponent</type>
</actionOverrides>""",
        "good_example": """<!-- Ensure component exists in force-app/main/default/lwc/ or remove override -->""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_customobject.htm"
    },
    "SFDX-FLS-001": {
        "title": "Non-Contiguous FieldPermissions XML",
        "category": "Metadata Deployment Integrity",
        "severity": "HIGH",
        "description": "A Profile or PermissionSet metadata XML file contains non-contiguous <fieldPermissions> element blocks.",
        "impact": "Salesforce Metadata API deploy fails with XML parsing errors or rejects split permissions. Hand-editing or bad merge conflict resolution causes this defect.",
        "bad_example": """<Profile>
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Active__c</field>
        <readable>true</readable>
    </fieldPermissions>
    <layoutAssignments>...</layoutAssignments>
    <!-- Non-contiguous! Second fieldPermissions block after layoutAssignments -->
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Rating</field>
        <readable>true</readable>
    </fieldPermissions>
</Profile>""",
        "good_example": """<!-- Group all elements of the same type together contiguously -->
<Profile>
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Active__c</field>
        <readable>true</readable>
    </fieldPermissions>
    <fieldPermissions>
        <editable>true</editable>
        <field>Account.Rating</field>
        <readable>true</readable>
    </fieldPermissions>
    <layoutAssignments>...</layoutAssignments>
</Profile>""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_profile.htm"
    },
    "AGENT-INVOC-003": {
        "title": "Reserved InvocableVariable Keyword",
        "category": "Agentforce Backing Logic",
        "severity": "CRITICAL",
        "description": "An @InvocableVariable in an Apex class uses a reserved Agent Script keyword ('model', 'description', 'label').",
        "impact": "Although valid in Apex, this causes 'SyntaxError: Unexpected <keyword>' during Agent Script bundle compilation.",
        "bad_example": """public class Request {
    @InvocableVariable(label='Description')
    public String description; // Reserved keyword in Agent Script!
}""",
        "good_example": """public class Request {
    @InvocableVariable(label='Description')
    public String issue_description; // Safe non-reserved identifier
}""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.agentforce.meta/agentforce/agent_script_overview.htm"
    },
    "AGENT-BUNDLE-002": {
        "title": "Agent Script Block Ordering Violation",
        "category": "Agentforce Script Integrity",
        "severity": "HIGH",
        "description": "Top-level blocks in .agent file violate mandatory order (system, config, variables, connection, knowledge, language, start_agent, subagent).",
        "impact": "Agent Script parser fails compilation with structural syntax errors.",
        "bad_example": """config:
    ...
system: # Wrong! system block must precede config
    ...""",
        "good_example": """system:
    ...
config:
    ...
variables:
    ...
start_agent router:
    ...""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.agentforce.meta/agentforce/agent_script_overview.htm"
    },
    "AGENT-BUNDLE-003": {
        "title": "Agent Script Lifecycle Hook & Scope Misuse",
        "category": "Agentforce Script Integrity",
        "severity": "HIGH",
        "description": "Lifecycle hook (before_reasoning/after_reasoning) wrapped in 'instructions: ->', or @inputs referenced in post-action 'set' directive.",
        "impact": "Wrapping hooks with instructions causes compile failure. Accessing @inputs in post-action set causes silent runtime drops leaving variables unassigned.",
        "bad_example": """before_reasoning:
    instructions: -> # Compile error!
        set @variables.x = True

# OR post-action @inputs misuse:
run @actions.do_work
    with input_val = ...
    set @variables.val = @inputs.input_val # Fails silently at runtime!""",
        "good_example": """before_reasoning:
    set @variables.x = True # Direct statements under hook

run @actions.do_work
    with input_val = ...
    set @variables.val = @outputs.result_val # Use @outputs or capture before call""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.agentforce.meta/agentforce/agent_script_overview.htm"
    },
    "AGENT-SAFETY-001": {
        "title": "Agentforce AI Identity Disclosure Missing",
        "category": "Agentforce Safety & Governance",
        "severity": "HIGH",
        "description": "Agent system instructions lack clear AI disclosure or transparent identity guidance.",
        "impact": "Violates Salesforce Trust and regulatory AI compliance (impersonation risk, lack of transparency).",
        "bad_example": """system:
    instructions: ->
        | You are Sarah, Senior Loan Underwriter at Bank Corp. (No AI disclosure!)""",
        "good_example": """system:
    instructions: ->
        | You are an AI virtual customer assistant helping users navigate their accounts.""",
        "reference": "https://www.salesforce.com/products/einstein/trust/"
    },

    # --------------------------------------------------------------------------
    # Salesforce Flow Best Practices & Governor Limits
    # --------------------------------------------------------------------------
    "FLOW-BULK-001": {
        "title": "Flow Data Element Inside Loop",
        "category": "Flow Architecture & Limits",
        "severity": "CRITICAL",
        "description": "A Salesforce Flow executes record lookups or DML operations (Create, Update, Delete) inside a loop element.",
        "impact": "Triggers 101 SOQL queries limit or 150 DML statements limit at runtime when processing batches of records.",
        "bad_example": """<!-- Inside <loops>: recordLookups or recordUpdates chained in nextValueConnector -->""",
        "good_example": """<!-- Loop assigns records to collection variable; single recordCreates/recordUpdates outside loop -->""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.salesforce_flow_limits.meta/salesforce_flow_limits/"
    },
    "FLOW-FAULT-001": {
        "title": "Flow Data Element Missing Fault Path",
        "category": "Flow Reliability & Exception Handling",
        "severity": "MEDIUM",
        "description": "A Flow record manipulation element lacks a <faultConnector> path.",
        "impact": "Any validation rule, trigger error, or lock contention causes an unhandled flow fault that crashes the user transaction.",
        "bad_example": """<recordUpdates>
    <name>Update_Account</name>
    <!-- Missing <faultConnector>! -->
</recordUpdates>""",
        "good_example": """<recordUpdates>
    <name>Update_Account</name>
    <faultConnector>
        <targetReference>Log_Flow_Error</targetReference>
    </faultConnector>
</recordUpdates>""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.salesforce_flow_limits.meta/salesforce_flow_limits/"
    },
    "FLOW-TIMING-001": {
        "title": "Same-Record Update in After-Save Flow",
        "category": "Flow Optimization & Timing",
        "severity": "HIGH",
        "description": "Record-triggered Flow performs update on $Record in an after-save context (RecordAfterSave).",
        "impact": "Causes duplicate DML transaction and re-invokes Apex triggers. 10x performance penalty compared to before-save.",
        "bad_example": """<!-- Flow triggerType: RecordAfterSave -->
<recordUpdates>
    <inputReference>$Record</inputReference>
</recordUpdates>""",
        "good_example": """<!-- Flow triggerType: RecordBeforeSave -->
<assignments>
    <assignToReference>$Record.Status__c</assignToReference>
    <value><stringValue>Active</stringValue></value>
</assignments>""",
        "reference": "https://developer.salesforce.com/docs/atlas.en-us.salesforce_flow_limits.meta/salesforce_flow_limits/"
    }
}

class SpecialistAdvisor:
    """Specialist Knowledge Advisor for developers and CI pipelines."""

    @staticmethod
    def get_rule_info(rule_id):
        return SPECIALIST_RULES.get(rule_id)

    @staticmethod
    def list_rules():
        return SPECIALIST_RULES

    @staticmethod
    def explain(rule_id):
        rule = SPECIALIST_RULES.get(rule_id)
        if not rule:
            return f"Error: Rule ID '{rule_id}' not recognized."
        
        lines = []
        lines.append("="*75)
        lines.append(f" SPECIALIST RULE: [{rule_id}] {rule['title']}")
        lines.append(f" Category: {rule['category']} | Severity: {rule['severity']}")
        lines.append("="*75)
        lines.append(f"\n📖 DESCRIPTION:\n{rule['description']}")
        lines.append(f"\n💥 REAL-WORLD IMPACT:\n{rule['impact']}")
        lines.append(f"\n❌ ANTI-PATTERN:\n{rule['bad_example']}")
        lines.append(f"\n✅ RECOMMENDED REMEDIATION:\n{rule['good_example']}")
        lines.append(f"\n🔗 OFFICIAL REFERENCE:\n{rule['reference']}\n")
        lines.append("="*75)
        return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Salesforce Specialist Advisor")
    parser.add_argument("--list-rules", action="store_true", help="List all cataloged specialist rules")
    parser.add_argument("--explain", type=str, metavar="RULE_ID", help="Explain a specific rule with full diagnostics")
    args = parser.parse_args()

    if args.list_rules:
        rules = SpecialistAdvisor.list_rules()
        print(f"\n{'='*80}")
        print(f" SALESFORCE SPECIALIST RULES CATALOG ({len(rules)} Rules)")
        print(f"{'='*80}\n")
        for rid, r in sorted(rules.items()):
            print(f"  [{rid:<18}] ({r['severity']:<8}) {r['title']}")
            print(f"    Category: {r['category']}")
        print(f"\n{'='*80}\n")
    elif args.explain:
        print(SpecialistAdvisor.explain(args.explain))
    else:
        parser.print_help()
