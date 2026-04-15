# SAST OWASP Dependency Check

A composite GitHub Action that builds a Spring Boot application and runs an [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) scan to detect known CVEs in project dependencies.

## What it does

1. **Restores Maven cache** — restores `~/.m2/repository` from a datetime-keyed cache to avoid re-downloading the OWASP CVE database on every run.
2. **Builds the Spring Boot app** — runs `mvn -B package -DskipTests`.
3. **Gets the current date** — stamps a datetime used as the Maven cache key.
4. **Runs Dependency Check** — executes `org.owasp:dependency-check-maven:check` and fails if any dependency exceeds the configured CVSS threshold.
5. **Saves Maven cache** — persists `~/.m2/repository` under the datetime key for future runs (always runs, even on scan failure).

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `nvd-api-key` | Yes | — | NVD API key for fetching the latest CVE database |
| `pom-file` | No | `pom.xml` | Path to the Maven POM file |
| `max-cvss-score` | No | `8` | Fail the scan if any dependency has a CVSS score above this value |
| `output-file` | No | `mvn-output.txt` | Path for the Maven build output log |
| `format` | No | `JSON` | Report format: `HTML`, `XML`, `CSV`, `JSON`, `JUNIT`, `SARIF`, or `ALL` |

## Usage

```yaml
on: workflow_dispatch

permissions:
  contents: read

jobs:
  owasp-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run OWASP Dependency Check
        uses: ./.github/actions/sast-owasp-dependency-check
        with:
          nvd-api-key: ${{ secrets.nvdApiKey }}
          pom-file: 'pom.xml'
          max-cvss-score: '8'
          output-file: 'mvn-output.txt'
```

See [`sast-owasp-dependency-check.yml`](../../workflows/sast-owasp-dependency-check.yml) for the full example workflow.
