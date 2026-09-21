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
