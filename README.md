# security-workflow-examples

This repository is a small Spring Boot sample used to demonstrate CI, dependency monitoring, and security scanning workflows in GitHub Actions.

## Current code snapshot

The application currently consists of a minimal Spring Boot service with a greeting helper and two REST endpoints:

- [src/main/java/com/example/App.java](src/main/java/com/example/App.java) — Spring Boot entry point and greeting logic
- [src/main/java/com/example/HelloController.java](src/main/java/com/example/HelloController.java) — REST controller exposing:
  - GET `/`
  - GET `/hello/{name}`
- [src/test/java/com/example/AppTest.java](src/test/java/com/example/AppTest.java) — unit tests for the greeting behavior
- [pom.xml](pom.xml) — Maven build file targeting Java 25 and Spring Boot 4.0.6
- [scripts/create-cve-issues.sh](scripts/create-cve-issues.sh) — helper script that turns OWASP Dependency Check output into GitHub issues

The build also pins an intentionally vulnerable dependency, `org.apache.logging.log4j:log4j-core:2.14.1`, to exercise vulnerability scanning and KEV-related workflows.

## Run locally

```bash
mvn test
mvn spring-boot:run
```

Then open:

- http://localhost:8080/
- http://localhost:8080/hello/Java

## Repository layout

- [src/main/java](src/main/java) — application source
- [src/test/java](src/test/java) — tests
- [.github/workflows](.github/workflows) — CI and security workflow definitions
- [.github/actions](.github/actions) — reusable workflow actions

## Security workflows present

- [.github/workflows/maven.yml](.github/workflows/maven.yml) — Maven build and dependency graph submission
- [.github/workflows/dependency-graph.yml](.github/workflows/dependency-graph.yml) — dependency graph upload
- [.github/workflows/sast-codeql.yml](.github/workflows/sast-codeql.yml), [.github/workflows/sast-codacy.yml](.github/workflows/sast-codacy.yml), [.github/workflows/sast-osv-scanner.yml](.github/workflows/sast-osv-scanner.yml), [.github/workflows/sast-osv-scanner-container.yml](.github/workflows/sast-osv-scanner-container.yml), [.github/workflows/sast-owasp-dependency-check.yml](.github/workflows/sast-owasp-dependency-check.yml), and [.github/workflows/sast-poutine.yml](.github/workflows/sast-poutine.yml) — static analysis coverage
- [.github/workflows/dast-zap.yml](.github/workflows/dast-zap.yml) and [.github/workflows/dast-dastardly.yml](.github/workflows/dast-dastardly.yml) — dynamic analysis coverage
- [.github/workflows/risk-ai-advisor.yml](.github/workflows/risk-ai-advisor.yml) and [.github/workflows/risk-sla-gate.yml](.github/workflows/risk-sla-gate.yml) — release-risk and SLA compliance workflows
