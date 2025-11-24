<p align="center">
  <img src="https://img.shields.io/badge/Supply%20Chain-Security-red?style=for-the-badge" alt="Supply Chain Security">
  <img src="https://img.shields.io/badge/npm-Protected-green?style=for-the-badge&logo=npm" alt="npm Protected">
  <img src="https://img.shields.io/badge/GitHub%20Action-Ready-blue?style=for-the-badge&logo=github-actions" alt="GitHub Action">
  <img src="https://img.shields.io/badge/Community-Powered-orange?style=for-the-badge&logo=opensourceinitiative" alt="Community Powered">
</p>

<h1 align="center">Shai-Hulud 2.0 Detector</h1>

<p align="center">
  <strong>Protect your projects from the Shai-Hulud 2.0 npm supply chain attack</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#-help-us-protect-the-community">Report Package</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#contributing">Contributing</a>
</p>

---

> ## 🚨 Found a Compromised Package? Report It!
>
> **This project's effectiveness depends on community contributions.** If you discover a compromised package, please report it immediately:
>
> | Action | Link |
> |--------|------|
> | **Report Package** | [📦 Submit Package Report](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=package-report.yml) |
> | **Batch Submission** | [📋 Submit Multiple Packages](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=batch-submission.yml) |
> | **Report False Positive** | [❌ Flag Incorrect Detection](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=false-positive.yml) |
> | **Full Guide** | [📖 Package Database Guide](docs/PACKAGE_DATABASE.md) |
>
> **Every package you report helps protect millions of developers worldwide.**

---

## Table of Contents

- [About the Attack](#about-the-attack)
- [Quick Start](#quick-start)
- [**Help Us Protect the Community**](#-help-us-protect-the-community) ⭐
- [Installation](#installation)
  - [GitHub Action (Recommended)](#github-action-recommended)
  - [Local CLI Usage](#local-cli-usage)
  - [CI/CD Integration](#cicd-integration)
- [Usage Guide](#usage-guide)
  - [Basic Scanning](#basic-scanning)
  - [Advanced Configuration](#advanced-configuration)
  - [Monorepo Support](#monorepo-support)
  - [SARIF Reports](#sarif-reports)
  - [Using Action Outputs](#using-action-outputs)
- [Configuration](#configuration)
  - [Inputs Reference](#inputs-reference)
  - [Outputs Reference](#outputs-reference)
  - [Environment Variables](#environment-variables)
- [Supported File Types](#supported-file-types)
- [Understanding Results](#understanding-results)
- [Affected Packages Database](#affected-packages-database)
- [Indicators of Compromise](#indicators-of-compromise)
- [Incident Response Guide](#incident-response-guide)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

---

## About the Attack

On **November 24, 2025**, a sophisticated supply chain attack dubbed **"Shai-Hulud 2.0"** (also known as "The Second Coming") compromised the npm ecosystem in one of the largest coordinated attacks on open-source software.

### Attack Statistics

| Metric | Value |
|--------|-------|
| Compromised Packages | **790+** unique packages |
| Monthly Downloads Affected | **132+ million** |
| Malicious GitHub Repos Created | **25,000+** |
| Compromised GitHub Users | **350+** |
| Attack Start Time | Nov 24, 2025 03:16 GMT |

### Major Organizations Affected

- **Zapier** - Integration platform
- **ENS Domains** - Ethereum Name Service
- **PostHog** - Product analytics
- **AsyncAPI** - API specification
- **Postman** - API development
- **Voiceflow** - Conversational AI
- **BrowserBase** - Browser automation
- **Oku UI** - Vue components

### How the Attack Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK FLOW DIAGRAM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. npm install          2. preinstall hook        3. Download  │
│  ───────────────► ─────────────────────► ──────────────────►   │
│                      setup_bun.js             Bun runtime       │
│                                                                 │
│  4. Execute payload      5. Credential theft    6. Exfiltrate   │
│  ───────────────────► ──────────────────► ─────────────────►   │
│    bun_environment.js      TruffleHog scan     GitHub repos     │
│                                                                 │
│  7. Self-propagate       8. Create runner      9. Destroy       │
│  ────────────────────► ─────────────────► ─────────────────►   │
│    Infect 100+ pkgs       "SHA1HULUD"       Wipe on failure    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Detailed Attack Steps:**

1. **Package Installation** - Victim runs `npm install` with compromised dependency
2. **Lifecycle Hook Execution** - `preinstall` or `postinstall` script triggers
3. **Bun Runtime Download** - `setup_bun.js` downloads the Bun JavaScript runtime
4. **Payload Execution** - `bun_environment.js` runs the malicious payload
5. **Credential Harvesting** - Uses TruffleHog to scan for exposed secrets
6. **Data Exfiltration** - Uploads stolen credentials to attacker-controlled GitHub repos
7. **Self-Propagation** - Attempts to infect up to 100 additional npm packages
8. **Persistence** - Creates self-hosted GitHub runners named "SHA1HULUD"
9. **Destructive Failsafe** - Wipes home directory if authentication fails

---

## Quick Start

Get protected in **under 2 minutes**:

### Step 1: Create Workflow File

Create `.github/workflows/shai-hulud-check.yml` in your repository:

```yaml
name: Shai-Hulud 2.0 Security Check

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
        with:
          fail-on-critical: true
```

### Step 2: Commit and Push

```bash
git add .github/workflows/shai-hulud-check.yml
git commit -m "Add Shai-Hulud 2.0 security scanning"
git push
```

### Step 3: Check Results

View scan results in the Actions tab of your repository.

---

## 🌍 Help Us Protect the Community

<p align="center">
  <strong>🔑 THE SUCCESS OF THIS PROJECT DEPENDS ON YOU!</strong>
</p>

The Shai-Hulud 2.0 attack is evolving, and new compromised packages are being discovered regularly. **Our crowdsourced package database is only as good as the community that maintains it.**

### Why Your Contribution Matters

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   YOU DISCOVER    ───►    YOU REPORT    ───►    WE ADD IT      │
│   a bad package          via GitHub           to database       │
│                                                                 │
│                              │                                  │
│                              ▼                                  │
│                                                                 │
│   MILLIONS OF     ◄───    DETECTOR      ◄───    REPOS ARE      │
│   devs protected         scans projects        now protected   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### How to Report Packages

| What You Found | How to Report | Time Required |
|----------------|---------------|---------------|
| **Single compromised package** | [📦 Package Report Form](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=package-report.yml) | ~2 minutes |
| **Multiple packages** | [📋 Batch Submission Form](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=batch-submission.yml) | ~5 minutes |
| **False positive** | [❌ False Positive Form](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=false-positive.yml) | ~2 minutes |

### What Makes a Good Report?

**Minimum evidence needed** (at least one):
- ✅ Package contains `setup_bun.js` or `bun_environment.js`
- ✅ File hash matches known malicious hash
- ✅ Suspicious `postinstall` script that downloads external code
- ✅ Published during attack window (Nov 24, 2025)
- ✅ Security advisory from npm/GitHub
- ✅ Analysis from security researcher

### Quick Report Template

Found a bad package? Copy this to create an issue:

```markdown
**Package:** @scope/package-name
**npm:** https://www.npmjs.com/package/@scope/package-name
**Severity:** critical

**Evidence:**
- [ ] Contains setup_bun.js
- [ ] Contains bun_environment.js
- [ ] Suspicious postinstall script
- [ ] Other: [describe]

**How I found it:** [Your discovery method]
```

### For Security Researchers

If you're doing systematic analysis and finding multiple packages:

1. **Use our [Batch Submission Form](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=batch-submission.yml)** for efficiency
2. **Read the full [Package Database Guide](docs/PACKAGE_DATABASE.md)** for detailed instructions
3. **Consider submitting a PR** directly to `master-packages.json` for faster integration
4. **We'll credit you** in our acknowledgments!

### Database Statistics

| Metric | Count |
|--------|-------|
| Total Packages | **790+** |
| Organizations | **50+** |
| Contributors | Growing! |
| Last Updated | See `master-packages.json` |

> **📖 Full Documentation:** [docs/PACKAGE_DATABASE.md](docs/PACKAGE_DATABASE.md)
>
> **🙏 Thank you to everyone who contributes. Together, we're making npm safer for everyone.**

---

## Installation

### GitHub Action (Recommended)

The easiest way to use Shai-Hulud Detector is as a GitHub Action.

#### Minimal Setup

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
```

#### Full Setup with All Options

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    fail-on-critical: true
    fail-on-high: false
    fail-on-any: false
    scan-lockfiles: true
    scan-node-modules: false
    output-format: text
    working-directory: '.'
```

### Local CLI Usage

You can also run the detector locally for development or CI systems without GitHub Actions:

#### Using npx (No Installation)

```bash
# Clone and run
git clone https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git
cd Shai-Hulud-2.0-Detector
npm install
node dist/index.js
```

#### Environment Variables for Local Use

```bash
# Set inputs via environment variables
export INPUT_FAIL-ON-CRITICAL=true
export INPUT_SCAN-LOCKFILES=true
export INPUT_OUTPUT-FORMAT=json
export INPUT_WORKING-DIRECTORY=/path/to/your/project

node dist/index.js
```

### CI/CD Integration

#### GitLab CI

```yaml
# .gitlab-ci.yml
shai-hulud-scan:
  image: node:20
  stage: test
  script:
    - git clone https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git /tmp/detector
    - cd /tmp/detector && npm ci
    - |
      export INPUT_FAIL-ON-CRITICAL=true
      export INPUT_WORKING-DIRECTORY=$CI_PROJECT_DIR
      node /tmp/detector/dist/index.js
  only:
    changes:
      - package.json
      - package-lock.json
      - yarn.lock
```

#### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    git clone https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git /tmp/detector
                    cd /tmp/detector && npm ci
                    export INPUT_FAIL-ON-CRITICAL=true
                    export INPUT_WORKING-DIRECTORY=${WORKSPACE}
                    node /tmp/detector/dist/index.js
                '''
            }
        }
    }
}
```

#### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  paths:
    include:
      - package.json
      - package-lock.json

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'

  - script: |
      git clone https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git /tmp/detector
      cd /tmp/detector && npm ci
      export INPUT_FAIL-ON-CRITICAL=true
      export INPUT_WORKING-DIRECTORY=$(Build.SourcesDirectory)
      node /tmp/detector/dist/index.js
    displayName: 'Shai-Hulud Security Scan'
```

#### CircleCI

```yaml
# .circleci/config.yml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Shai-Hulud Security Scan
          command: |
            git clone https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git /tmp/detector
            cd /tmp/detector && npm ci
            export INPUT_FAIL-ON-CRITICAL=true
            export INPUT_WORKING-DIRECTORY=$(pwd)
            node /tmp/detector/dist/index.js

workflows:
  main:
    jobs:
      - security-scan
```

---

## Usage Guide

### Basic Scanning

#### Scan on Every Push

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
```

#### Scan Only Dependency Files

```yaml
name: Security Scan
on:
  push:
    paths:
      - '**/package.json'
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/pnpm-lock.yaml'
  pull_request:
    paths:
      - '**/package.json'
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/pnpm-lock.yaml'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
```

#### Scheduled Daily Scans

```yaml
name: Daily Security Scan
on:
  schedule:
    - cron: '0 0 * * *'  # Run at midnight UTC
  workflow_dispatch:      # Allow manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
        with:
          fail-on-any: true
```

### Advanced Configuration

#### Block PRs with Compromised Dependencies

```yaml
name: PR Security Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for Shai-Hulud 2.0
        id: scan
        uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
        with:
          fail-on-critical: true
          fail-on-high: true

      - name: Comment on PR if affected
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## ⚠️ Security Alert: Shai-Hulud 2.0 Attack Detected\n\nThis PR contains dependencies compromised in the Shai-Hulud 2.0 supply chain attack.\n\n**Action Required:** Remove or update the affected packages before merging.'
            })
```

#### Strict Mode - Fail on Any Detection

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    fail-on-any: true
```

#### Warning Mode - Report but Don't Fail

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    fail-on-critical: false
    fail-on-high: false
    fail-on-any: false
```

### Monorepo Support

The detector automatically scans subdirectories for package files (up to 5 levels deep).

#### Scan Entire Monorepo

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    working-directory: '.'
    scan-lockfiles: true
```

#### Scan Specific Package

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    working-directory: './packages/frontend'
```

#### Matrix Strategy for Multiple Packages

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        package: [frontend, backend, shared, cli]
    steps:
      - uses: actions/checkout@v4
      - uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
        with:
          working-directory: './packages/${{ matrix.package }}'
```

### SARIF Reports

Generate SARIF reports for GitHub Security tab integration:

#### Basic SARIF Output

```yaml
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    output-format: sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: shai-hulud-results.sarif
```

#### Full Security Integration

```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Shai-Hulud Scan
        uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
        with:
          output-format: sarif
          fail-on-critical: false  # Don't fail, just report

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: shai-hulud-results.sarif
          category: shai-hulud-detector
```

### Using Action Outputs

Access scan results for conditional logic or notifications:

```yaml
- name: Run Scan
  id: scan
  uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
  with:
    fail-on-critical: false
    output-format: json

- name: Process Results
  run: |
    echo "Status: ${{ steps.scan.outputs.status }}"
    echo "Affected packages: ${{ steps.scan.outputs.affected-count }}"
    echo "Scan time: ${{ steps.scan.outputs.scan-time }}ms"

- name: Send Slack Notification
  if: steps.scan.outputs.status == 'affected'
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "⚠️ Shai-Hulud 2.0 Alert: ${{ steps.scan.outputs.affected-count }} compromised packages detected in ${{ github.repository }}"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

---

## Configuration

### Inputs Reference

| Input | Description | Type | Default |
|-------|-------------|------|---------|
| `fail-on-critical` | Fail workflow if critical severity packages are found | `boolean` | `true` |
| `fail-on-high` | Fail workflow if high or critical severity packages are found | `boolean` | `false` |
| `fail-on-any` | Fail workflow if any compromised packages are found | `boolean` | `false` |
| `scan-lockfiles` | Scan lockfiles for transitive dependencies | `boolean` | `true` |
| `scan-node-modules` | Scan node_modules directory (slower, more thorough) | `boolean` | `false` |
| `output-format` | Output format: `text`, `json`, or `sarif` | `string` | `text` |
| `working-directory` | Directory to scan (relative to repository root) | `string` | `.` |

### Outputs Reference

| Output | Description | Example |
|--------|-------------|---------|
| `affected-count` | Number of compromised packages detected | `3` |
| `status` | Overall scan status | `clean` or `affected` |
| `scan-time` | Scan duration in milliseconds | `156` |
| `results` | JSON array of detected packages | `[{"package":"posthog-node",...}]` |
| `sarif-file` | Path to generated SARIF file (when output-format is sarif) | `shai-hulud-results.sarif` |

### Environment Variables

When running locally or in non-GitHub CI systems:

| Variable | Maps To | Example |
|----------|---------|---------|
| `INPUT_FAIL-ON-CRITICAL` | `fail-on-critical` input | `true` |
| `INPUT_FAIL-ON-HIGH` | `fail-on-high` input | `false` |
| `INPUT_FAIL-ON-ANY` | `fail-on-any` input | `false` |
| `INPUT_SCAN-LOCKFILES` | `scan-lockfiles` input | `true` |
| `INPUT_OUTPUT-FORMAT` | `output-format` input | `json` |
| `INPUT_WORKING-DIRECTORY` | `working-directory` input | `/app` |

---

## Supported File Types

| File | Format | Direct Deps | Transitive Deps |
|------|--------|-------------|-----------------|
| `package.json` | JSON | ✅ | ❌ |
| `package-lock.json` | JSON (v1, v2, v3) | ✅ | ✅ |
| `yarn.lock` | Yarn custom format | ❌ | ✅ |
| `npm-shrinkwrap.json` | JSON | ✅ | ✅ |
| `pnpm-lock.yaml` | YAML | 🚧 Coming soon | 🚧 |

---

## Understanding Results

### Output Formats

#### Text Output (Default)

```
============================================================
  SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR
============================================================

  STATUS: AFFECTED (2 package(s) found)

  AFFECTED PACKAGES:
------------------------------------------------------------
  [CRITICAL] posthog-node@5.13.3 (direct)
         Location: package.json
  [CRITICAL] @asyncapi/parser@3.4.2 (transitive)
         Location: package-lock.json

------------------------------------------------------------
  Files scanned: 2
  Scan time: 67ms
  Database version: 1.0.0
============================================================

  IMMEDIATE ACTIONS REQUIRED:
  1. Do NOT run npm install until packages are updated
  2. Rotate all credentials (npm, GitHub, AWS, etc.)
  3. Check for unauthorized GitHub self-hosted runners named "SHA1HULUD"
  4. Audit GitHub repos for "Shai-Hulud: The Second Coming" description
```

#### JSON Output

```json
{
  "totalDependencies": 150,
  "affectedCount": 2,
  "cleanCount": 148,
  "results": [
    {
      "package": "posthog-node",
      "version": "5.13.3",
      "severity": "critical",
      "isDirect": true,
      "location": "package.json"
    },
    {
      "package": "@asyncapi/parser",
      "version": "3.4.2",
      "severity": "critical",
      "isDirect": false,
      "location": "package-lock.json"
    }
  ],
  "scannedFiles": ["package.json", "package-lock.json"],
  "scanTime": 67
}
```

### Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Confirmed compromised package from the attack | Remove immediately |
| **HIGH** | Suspected compromised or related package | Investigate and remove |
| **MEDIUM** | Package from affected organization | Monitor closely |
| **LOW** | Potentially related package | Review when possible |

### Direct vs Transitive

- **Direct**: Package is listed in your `package.json`
- **Transitive**: Package is a dependency of one of your dependencies

---

## Affected Packages Database

The detector includes a database of **790 unique packages** identified in the attack:

| Organization | Count | Key Packages |
|--------------|-------|--------------|
| AsyncAPI | 36 | `@asyncapi/cli`, `@asyncapi/parser`, `@asyncapi/generator` |
| PostHog | 62 | `posthog-node`, `posthog-js`, `@posthog/nextjs`, `@posthog/plugin-server` |
| ENS Domains | 46 | `@ensdomains/ensjs`, `@ensdomains/thorin`, `@ensdomains/ui` |
| Zapier | 16 | `zapier-platform-core`, `zapier-platform-cli`, `@zapier/ai-actions` |
| Voiceflow | 57 | `@voiceflow/common`, `@voiceflow/sdk-runtime`, `@voiceflow/api-sdk` |
| Postman | 17 | `@postman/tunnel-agent`, `@postman/mcp-server`, `@postman/csv-parse` |
| BrowserBase | 7 | `@browserbasehq/stagehand`, `@browserbasehq/mcp`, `@browserbasehq/sdk-functions` |
| Oku UI | 41 | `@oku-ui/primitives`, `@oku-ui/dialog`, `@oku-ui/toast` |
| Others | 508 | Various community packages |

### Database Updates

The package database is updated when:
- New compromised packages are identified
- False positives are reported and verified
- Organizations release remediated versions

Check `master-packages.json` for the full list with version information.

---

## Indicators of Compromise

### Malicious Files

If you find these files in your `node_modules`, you may be compromised:

| File | SHA-1 Hash | Purpose |
|------|------------|---------|
| `setup_bun.js` | `d1829b4708126dcc7bea7437c04d1f10eacd4a16` | Downloads Bun runtime |
| `bun_environment.js` | `d60ec97eea19fffb4809bc35b91033b52490ca11` | Executes malicious payload |
| `cloud.json` | - | Stores stolen cloud credentials |
| `contents.json` | - | Contains exfiltrated data |
| `environment.json` | - | Holds environment variables |
| `truffleSecrets.json` | - | TruffleHog scan results |

### Malicious Workflows

Check `.github/workflows/` for:
- `discussion.yaml` - Injected workflow for remote execution
- `formatter_*.yml` - Malicious workflow with random suffix

### GitHub Indicators

Search your organization for:
- Self-hosted runners named `SHA1HULUD`
- Repositories with description containing `Shai-Hulud: The Second Coming`

---

## Incident Response Guide

### If You're Affected

#### Immediate Actions (First 15 Minutes)

1. **STOP** - Do not run `npm install` or any build commands
2. **Isolate** - Disconnect affected systems from network if possible
3. **Document** - Note timestamps, affected systems, and what was run
4. **Alert** - Notify your security team

#### Containment (First Hour)

```bash
# 1. Check for malicious files
find ./node_modules -name "setup_bun.js" -o -name "bun_environment.js"

# 2. Check for malicious workflows
ls -la .github/workflows/ | grep -E "(discussion|formatter_)"

# 3. Check for unauthorized runners (requires gh CLI)
gh api repos/{owner}/{repo}/actions/runners --jq '.runners[].name' | grep -i sha1hulud
```

#### Credential Rotation Checklist

| Service | Action | Priority |
|---------|--------|----------|
| npm | Revoke and regenerate tokens | 🔴 Critical |
| GitHub | Rotate PATs, OAuth tokens, App keys | 🔴 Critical |
| AWS | Rotate access keys, invalidate sessions | 🔴 Critical |
| GCP | Rotate service account keys | 🔴 Critical |
| Azure | Regenerate service principal credentials | 🔴 Critical |
| Docker Hub | Reset access tokens | 🟡 High |
| Database | Change passwords, rotate connection strings | 🟡 High |
| Third-party APIs | Regenerate API keys | 🟡 High |
| SSH | Regenerate keys if stored in repo | 🟠 Medium |

#### Clean Installation

```bash
# 1. Remove existing node_modules
rm -rf node_modules package-lock.json

# 2. Clear npm cache
npm cache clean --force

# 3. Audit package.json manually
# Remove any compromised packages

# 4. Fresh install with audit
npm install --ignore-scripts  # Prevent postinstall hooks
npm audit

# 5. Run security scan
npx gensecaihq/Shai-Hulud-2.0-Detector
```

---

## FAQ

### General Questions

**Q: Is this a real attack?**
A: Yes. The Shai-Hulud 2.0 attack occurred on November 24, 2025, and compromised hundreds of npm packages.

**Q: How do I know if I'm affected?**
A: Run this detector on your project. If it reports affected packages, you may have been compromised.

**Q: What if I already ran npm install?**
A: Follow the [Incident Response Guide](#incident-response-guide) immediately. Assume credentials are compromised.

### Technical Questions

**Q: Does this scan my actual code?**
A: No. It only scans `package.json`, lockfiles, and optionally `node_modules` for known compromised package names.

**Q: Will this slow down my CI/CD?**
A: No. Typical scan time is under 100ms. The detector is optimized for speed.

**Q: Does this work with private registries?**
A: Yes. The detector reads local files and doesn't need registry access.

**Q: Can I use this with Yarn 2/3 (Berry)?**
A: Yarn Classic lockfiles are supported. Yarn Berry (PnP) support is coming soon.

### False Positives

**Q: What if a package is flagged incorrectly?**
A: [Open an issue](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues) with details. We'll investigate and update the database.

**Q: What about patched versions?**
A: Currently, all versions are flagged. We're working on version-specific detection.

---

## Contributing

We welcome contributions! Here's how you can help:

> **Want to report a compromised package?** See our detailed [Package Database Contribution Guide](docs/PACKAGE_DATABASE.md) for step-by-step instructions on submitting packages via GitHub Issues or Pull Requests.

### Quick Links

| Action | Link |
|--------|------|
| Report compromised package | [Package Report Issue](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=package-report.yml) |
| Report false positive | [False Positive Issue](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=false-positive.yml) |
| Batch submission | [Batch Submission Issue](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=batch-submission.yml) |
| Contribution guide | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Package database guide | [docs/PACKAGE_DATABASE.md](docs/PACKAGE_DATABASE.md) |

### Reporting Issues

- **Compromised Packages**: Use the [Package Report](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=package-report.yml) template
- **False Positives**: Use the [False Positive](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=false-positive.yml) template
- **Multiple Packages**: Use the [Batch Submission](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=batch-submission.yml) template
- **Bugs**: Open an issue with reproduction steps

### Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/Shai-Hulud-2.0-Detector.git
cd Shai-Hulud-2.0-Detector

# 2. Install dependencies
npm install

# 3. Make changes to src/

# 4. Build
npm run build

# 5. Test locally
export INPUT_WORKING-DIRECTORY=/path/to/test/project
node dist/index.js
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `npm run build` to compile
5. Test your changes
6. Commit (`git commit -m 'Add amazing feature'`)
7. Push (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style

- TypeScript with strict mode
- Use meaningful variable names
- Add comments for complex logic
- Follow existing patterns in the codebase

### Updating Package Database

> **Full Guide:** See [docs/PACKAGE_DATABASE.md](docs/PACKAGE_DATABASE.md) for detailed instructions, evidence requirements, and submission templates.

**Quick steps to add a package:**

1. **Via GitHub Issue** (Easiest):
   - Use the [Package Report](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues/new?template=package-report.yml) template
   - Fill in package details and evidence
   - Maintainers will review and add

2. **Via Pull Request** (For contributors):
   ```bash
   # Fork and clone the repo
   git checkout -b add-package/package-name

   # Edit master-packages.json - add to packages array:
   {
     "name": "@scope/package-name",
     "severity": "critical",
     "affectedVersions": ["*"]
   }

   # Build and submit
   npm run build
   git commit -am "feat(db): add @scope/package-name"
   git push && gh pr create
   ```

**Evidence required:** At least one of - malicious file found, hash match, suspicious script, security advisory, or maintainer compromise confirmation.

---

## Acknowledgments

### Security Researchers

This project builds on the excellent work of security researchers who identified and analyzed the Shai-Hulud 2.0 attack:

- **[Aikido Security](https://www.aikido.dev)** - Initial detection and detailed analysis
- **[Wiz.io](https://www.wiz.io)** - Comprehensive threat investigation
- **[HelixGuard](https://helixguard.ai)** - Malware analysis and IOC identification

### Research & Analysis

- [Aikido Security Blog - Shai-Hulud Strikes Again](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [Wiz.io Blog - Shai-Hulud 2.0 Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [HelixGuard Blog - Malicious SHA1HULUD Analysis](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

### Open Source Tools

- [GitHub Actions](https://github.com/features/actions) - CI/CD platform
- [ncc](https://github.com/vercel/ncc) - TypeScript compilation
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning (used by attackers, ironic)

### Community

Thanks to everyone who reported affected packages, tested the detector, and helped spread awareness about this attack.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 gensecaihq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Security Policy

### Reporting Vulnerabilities

If you discover a security vulnerability in this detector tool itself, please report it responsibly:

1. **Do NOT** open a public issue
2. Email security concerns to the maintainers
3. Allow 48 hours for initial response
4. Coordinate disclosure timeline

### Scope

This tool is for **defensive security purposes only**. It:
- Detects known compromised packages
- Does NOT guarantee detection of all variants
- Does NOT protect against future attacks
- Should be used alongside other security measures

---

<p align="center">
  <strong>Stay safe. Protect your supply chain. 🛡️</strong>
</p>

<p align="center">
  <a href="https://github.com/gensecaihq/Shai-Hulud-2.0-Detector">⭐ Star this repo</a> •
  <a href="https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues">🐛 Report Bug</a> •
  <a href="https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues">💡 Request Feature</a>
</p>
