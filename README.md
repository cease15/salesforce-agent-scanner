# 🛡️ Salesforce Specialist Agent Scanner (`sf-agent-scan`)

Universal, compiler-grade quality, security, and architecture scanner for Salesforce repositories. Designed to enforce elite Salesforce engineering standards across **all CI/CD pipelines (GitHub Actions, Azure DevOps, Jenkins, GitLab CI)** and local developer environments.

---

## 🚀 Key Capabilities & Gate Scopes

### 1. Metadata Security & Access Control
- **External & Community PII Protection**: Prevents exposure of sensitive fields (`SSN_TIN_ID__c`, `Tax_ID__c`, `DOB__c`, `Routing_Number__c`) on public and community profiles.
- **Guest User Lockdown**: Enforces Salesforce secure guest user record access policies (bans ModifyAll/ViewAll/Edit/Delete permissions on guest profiles).
- **Profile & Permission Set Elevation**: Detects dangerous administrative permissions (`AuthorApex`, `ModifyAllData`, `ManageUsers`) assigned to non-admin personas.

### 2. Apex Specialist Verifier (`/apex*`)
- **Trigger Architecture**: Enforces single trigger per sObject and requires delegation to logic-less handler classes. Flags inline SOQL/DML in triggers.
- **AST Bulkification & Governor Limits**: Scans loop structures (`for`, `while`, `do-while`) for nested SOQL queries (`APEX-BULK-001`) and DML statements (`APEX-BULK-002`).
- **Sharing Model Enforcement**: Verifies all `@AuraEnabled` and `@RestResource` controllers explicitly declare `with sharing` or `inherited sharing` (`APEX-SEC-001`).
- **SOQL Injection Prevention**: Detects unsanitized dynamic SOQL query string concatenations lacking bind variables or `String.escapeSingleQuotes()`.
- **Test Quality & Portability**: Flags `seeAllData=true`, hardcoded sandbox usernames (`@test.com.dev`), hardcoded record IDs, and verifies `@isTest` classes contain meaningful assertions.
- **Org Coverage Verification**: Integrates with Salesforce Tooling API to audit live code coverage and detect 0% triggers.

### 3. LWC Specialist Verifier (`/lwc*`)
- **DOM Sanitization & XSS**: Detects `innerHTML`, `outerHTML`, and `insertAdjacentHTML` bypasses of the LWC template engine (`LWC-DOM-001`).
- **Reactivity & Immutability**: Flags direct assignment or mutation of public `@api` properties by child components (`LWC-REACT-001`).
- **Navigation Architecture**: Enforces `lightning/navigation` (`NavigationMixin`) over raw `window.location` manipulations (`LWC-NAV-001`).
- **Environment Decoupling**: Detects hardcoded sandbox URLs and hardcoded record IDs in JavaScript controllers (`LWC-ENV-001`, `LWC-ENV-002`).
- **Accessibility (WCAG 2.1 AA)**: Flags interactive elements (buttons, inputs, links) lacking `aria-label`, `title`, or inner text (`LWC-A11Y-001`).
- **Component Metadata Integrity**: Validates `isExposed`, `targets`, and `apiVersion` declarations.

---

## 📦 Usage Across Pipelines

### Option A: Universal GitHub Action (Composite)

Add to `.github/workflows/quality-gate.yml`:

```yaml
name: Salesforce Quality Gate
on: [pull_request, push]

jobs:
  salesforce-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # Required for SARIF Code Scanning
      checks: write           # Required for JUnit annotations
    steps:
      - uses: actions/checkout@v4

      - name: Run Salesforce Specialist Scanner
        uses: cease15/salesforce-agent-scanner@v1
        with:
          scope: all          # all | apex | lwc | security
          strict: 'true'      # Fail PR build if critical/high issues found
          sarif-file: 'results.sarif'
          junit-file: 'junit.xml'
          upload-sarif: 'true'
```

### Option B: Zero-Config GitHub Workflow Template

Copy `templates/workflows/salesforce-gate.yml` into your target repository's `.github/workflows/salesforce-gate.yml`:

```yaml
name: Salesforce Quality Gate
on: [pull_request, push]

jobs:
  salesforce-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      checks: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Salesforce Quality Gate
        uses: cease15/salesforce-agent-scanner@v1
        with:
          scope: all
          strict: 'true'
          upload-sarif: 'true'
```

### Option C: Azure DevOps Pipeline

In your `azure-pipelines.yml`:

```yaml
trigger:
  - main
  - develop

pr:
  - main
  - develop

jobs:
  - job: SalesforceScan
    displayName: 'Salesforce Specialist Agent Quality Gate'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
      - template: templates/azure-pipelines-scanner.yml@self
        parameters:
          scope: 'all'
          strict: true
```

Or via direct inline script:

```bash
curl -sSL https://raw.githubusercontent.com/cease15/salesforce-agent-scanner/main/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"

sf-agent-scan --all --ado --junit $(Build.ArtifactStagingDirectory)/junit.xml --strict
```

---

## 💻 Local Developer & CLI Usage

### One-Line Install
```bash
curl -sSL https://raw.githubusercontent.com/cease15/salesforce-agent-scanner/main/install.sh | bash
```

### Python Pip Install
```bash
pip install git+https://github.com/cease15/salesforce-agent-scanner.git
```

### Command-Line Arguments

```text
sf-agent-scan [-h] [--repo-dir REPO_DIR] [--scope {all,apex,lwc,security}]
              [--apex] [--lwc] [--security] [--all]
              [--target-org TARGET_ORG] [--strict] [--no-strict]
              [--sarif SARIF] [--junit JUNIT] [--json]
              [--summary-md SUMMARY_MD] [--ado]
```

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--repo-dir` | Root directory of the Salesforce repository | `.` |
| `--scope` | Scan scope: `all`, `apex`, `lwc`, `security` | `all` |
| `--apex` | Run Apex specialist verification only | `False` |
| `--lwc` | Run LWC specialist verification only | `False` |
| `--security` | Run metadata security and access control only | `False` |
| `--target-org` | Salesforce CLI org alias for live Tooling API coverage checks | `None` |
| `--strict` | Enforce failure (exit code 1) on critical/high findings | `True` |
| `--sarif` | Output file path for SARIF 2.1.0 report | `None` |
| `--junit` | Output file path for JUnit XML test report | `None` |
| `--summary-md` | Output file path for Markdown summary (`$GITHUB_STEP_SUMMARY`) | `None` |
| `--ado` | Emit native Azure DevOps logging commands (`##vso[...]`) | `False` |

---

## 📊 Output Formats

1. **GitHub Code Scanning (SARIF 2.1.0)**: Annotates vulnerabilities directly on PR code diffs and in the repository Security tab.
2. **JUnit XML**: Integrates natively with GitHub PR Checks and Azure DevOps Test Runs tab via `PublishTestResults@2`.
3. **Markdown Step Summary**: Produces visual tables with collapsible detail blocks in GitHub Actions job summaries.
4. **Azure DevOps Commands**: Emits `##vso[task.logissue type=error]` and `##vso[task.logissue type=warning]` with exact file paths and line numbers.

---

## 📄 License
MIT License. Authored and maintained by `cease15 <cease15@gmail.com>`.
