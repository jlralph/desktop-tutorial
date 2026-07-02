# security-workflow-examples

A Spring Boot web application instrumented with automated CI, dependency graph submission, and a broad security scanning pipeline.

## Stack

- **Java 25**
- **Spring Boot 4.0.6**
- **Maven**
- Spring Web, Spring Boot Actuator, Spring Boot Test
- Includes an intentionally vulnerable dependency: `org.apache.logging.log4j:log4j-core:2.14.1` for security scan demonstration

## Application snapshot

- `src/main/java/com/example/App.java` — Spring Boot entry point + greeting helper
- `src/main/java/com/example/HelloController.java` — REST endpoints
  - GET `/`
  - GET `/hello/{name}`
- `src/test/java/com/example/AppTest.java` — unit tests for greeting behavior

## CI / GitHub Actions

- `.github/workflows/maven.yml` — manual Java CI build with Maven and dependency graph submission
- `.github/workflows/dependency-graph.yml` — dependency graph upload on push

## SAST (Static Analysis)

- `.github/workflows/sast-codeql.yml`
- `.github/workflows/sast-codacy.yml`
- `.github/workflows/sast-osv-scanner.yml`
- `.github/workflows/sast-osv-scanner-container.yml`
- `.github/workflows/sast-owasp-dependency-check.yml`
- `.github/workflows/sast-poutine.yml`

## DAST (Dynamic Analysis)

- `.github/workflows/dast-zap.yml`
- `.github/workflows/dast-dastardly.yml`

## Risk and compliance workflows

- `.github/workflows/risk-ai-advisor.yml` — AI-weighted release-risk verdict over open CodeQL and Dependabot alerts (advisory by default). Supports `workflow_dispatch` inputs for the **deployment environment** (defaults to `production - internet facing`; calibrates exposure/blast radius), the `fail-on` blocking threshold, and the GitHub Models `model`.
- `.github/workflows/risk-sla-gate.yml`

## Custom Actions

- `.github/actions/my-action/`
- `.github/actions/risk_ai_advisor/`
- `.github/actions/risk_sla_gate/`
- `.github/actions/sast-osv-scanner-container/`
- `.github/actions/sast-owasp-dependency-check/`
- `.github/actions/dast-dastardly/`

## Scripts

- `scripts/create-cve-issues.sh` — parses OWASP Dependency Check JSON output and synchronizes GitHub issues for detected CVEs

## Badges

[![Java CI with Maven](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/maven.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/maven.yml)

[![Dependency Graph](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dependency-graph.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dependency-graph.yml)

[![SAST (CodeQL)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-codeql.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-codeql.yml)

[![SAST (Codacy)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-codacy.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-codacy.yml)

[![SAST (OSV-Scanner)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-osv-scanner.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-osv-scanner.yml)

[![SAST (OSV-Scanner-Container)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-osv-scanner-container.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-osv-scanner-container.yml)

[![SAST (OWASP Dependency Check)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-owasp-dependency-check.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-owasp-dependency-check.yml)

[![SAST (Poutine)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-poutine.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/sast-poutine.yml)

[![DAST (Checkmarx ZAP)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dast-zap.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dast-zap.yml)

[![DAST (Dastardly)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dast-dastardly.yml/badge.svg)](https://github.com/jlralph/security-scan-workflow-examples/actions/workflows/dast-dastardly.yml)
