# security-scan-workflows-examples

A Spring Boot web application with a fully automated CI and security scanning pipeline.

## Stack

- **Java 25** / **Spring Boot 4.0.6**
- **Maven** (build & dependency management)
- Spring Web, Spring Boot Actuator, Spring Boot Test

## CI/CD & Security Workflows

### Build
| Workflow | Trigger | Description |
|---|---|---|
| Java CI with Maven | manual | Builds the project with Maven and uploads the dependency graph to GitHub |

### SAST (Static Analysis)
| Workflow | Trigger | Description |
|---|---|---|
| CodeQL | manual | GitHub's semantic code analysis for vulnerability detection |
| Codacy | manual | Code quality and security analysis |
| OSV-Scanner | manual | Open-source vulnerability scanning against the OSV database |
| OSV-Scanner (Container) | manual | Scans a container image for vulnerabilities and syncs findings to GitHub Issues |
| OWASP Dependency Check | manual | Checks dependencies against known CVEs and syncs findings to GitHub Issues (create, update, close) |
| Poutine | manual | Supply-chain security analysis for GitHub Actions |

### DAST (Dynamic Analysis)
| Workflow | Trigger | Description |
|---|---|---|
| Checkmarx ZAP | manual | Builds and starts the Spring Boot app, then runs a full ZAP scan against `http://localhost:8080` |
| Dastardly | manual | Lightweight DAST scan using Burp Suite's Dastardly |

## Custom Actions

| Action | Description |
|---|---|
| [my-action](.github/actions/my-action/) | General-purpose action (Node 20 runtime) |
| [sast-osv-scanner-container](.github/actions/sast-osv-scanner-container/) | Scans a container image with OSV Scanner and syncs GitHub Issues |
| [sast-owasp-dependency-check](.github/actions/sast-owasp-dependency-check/) | Builds the Spring Boot app, runs an OWASP Dependency Check scan, and syncs CVE findings to GitHub Issues |
| [dast-dastardly](.github/actions/dast-dastardly/) | Builds the Spring Boot app and runs a Dastardly DAST scan |

## Scripts

| Script | Description |
|---|---|
| [scripts/create-cve-issues.sh](scripts/create-cve-issues.sh) | Parses an OWASP Dependency Check JSON report and syncs findings to GitHub Issues — creates issues for new CVEs, updates issues when vulnerable packages change, and closes issues for CVEs no longer detected |

## Badges

[![DAST (Checkmarx ZAP)](https://github.com/jlralph/desktop-tutorial/actions/workflows/dast-zap.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/dast-zap.yml)

[![DAST (Dastardly)](https://github.com/jlralph/desktop-tutorial/actions/workflows/dast-dastardly.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/dast-dastardly.yml)

[![SAST (Codacy)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-codacy.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-codacy.yml)

[![SAST (CodeQL)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-codeql.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-codeql.yml)

[![SAST (OSV-Scanner)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-osv-scanner.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-osv-scanner.yml)

[![SAST (OSV-Scanner-Container)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-osv-scanner-container.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-osv-scanner-container.yml)

[![SAST (OWASP Dependency Check)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-owasp-dependency-check.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-owasp-dependency-check.yml)

[![SAST (Poutine)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-poutine.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/sast-poutine.yml)

[![Java CI with Maven](https://github.com/jlralph/desktop-tutorial/actions/workflows/maven.yml/badge.svg)](https://github.com/jlralph/desktop-tutorial/actions/workflows/maven.yml)
