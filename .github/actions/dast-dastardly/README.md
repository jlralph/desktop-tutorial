# DAST Dastardly Scan

A composite GitHub Action that builds a Spring Boot application, starts it, and runs a [Dastardly](https://portswigger.net/burp/dastardly) DAST scan against it.

## What it does

1. **Caches Maven packages** — restores and saves the `~/.m2` cache to speed up builds.
2. **Builds the Spring Boot app** — runs `mvn -B package -DskipTests`.
3. **Starts the app** — launches the built JAR as a background process.
4. **Waits for readiness** — polls the health-check endpoint until the app responds or retries are exhausted.
5. **Runs Dastardly** — executes a Dastardly scan via Docker against the running app and writes a JUnit XML report.
6. **Publishes the report** — uploads the JUnit XML report as a check run annotation (always runs, even on scan failure).

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target-url` | No | `http://localhost:8080` | Base URL of the running application to scan |
| `health-check-path` | No | `/actuator/health` | Path polled to confirm the app is ready |
| `pom-file` | No | `pom.xml` | Path to the Maven POM file |
| `report-path` | No | `dastardly-report.xml` | Output path for the Dastardly JUnit XML report |
| `startup-retries` | No | `30` | Number of 5-second retries while waiting for the app to start |

## Usage

```yaml
on: workflow_dispatch

permissions:
  contents: read
  checks: write

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Dastardly DAST scan
        uses: ./.github/actions/dast-dastardly
        with:
          target-url: 'http://localhost:8080'
          health-check-path: '/actuator/health'
          pom-file: 'pom.xml'
          report-path: 'dastardly-report.xml'
          startup-retries: '30'
```

See [`dast-dastardly.yml`](../../workflows/dast-dastardly.yml) for the full example workflow.
