# Dependency Checker CLI

[![Self Check Status](https://github.com/sambabib/dependency-checker/actions/workflows/self-check.yml/badge.svg)](https://github.com/sambabib/dependency-checker/actions/workflows/self-check.yml)

A command-line tool to analyze project dependencies and report outdated, incompatible, or problematic packages across multiple package ecosystems.

## Features

* **Multi-Ecosystem Support**:
  * Node.js/npm (`package.json`)
  * .NET/NuGet (`*.csproj`)
  * Python/Pip (`requirements.txt`)
  * Java/Maven (`pom.xml`)

* **Comprehensive Analysis**:
  * Checks for latest stable versions in respective package registries
  * Identifies outdated dependencies with severity levels (major, minor, patch)
  * Reports deprecated or yanked packages
  * Validates compatibility (peer dependencies, framework compatibility)

* **Flexible Output Options**:
  * Readable table format
  * JSON for programmatic processing
  * SARIF for CI/CD integration
  * File output support

* **Configuration System**:
  * YAML-based configuration (`.depcheck.yaml`)
  * Custom severity thresholds
  * Package exclusions
  * Custom registry URLs
  * Output format and destination settings

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/sambabib/dependency-checker.git
   cd dependency-checker
   ```

2. Build the executable:
   ```bash
   go build -o depcheck
   ```

3. (Optional) Move to your PATH:
   ```bash
   # Linux/macOS
   sudo mv depcheck /usr/local/bin/
   
   # Windows (run in PowerShell as Administrator)
   # Move to a directory in your PATH
   ```

## Usage

```bash
depcheck analyze -p <path-to-project> [flags]
```

### Command-Line Arguments

* `-p`, `--path` (string): Path to the project directory to analyze (required)
* `-f`, `--format` (string): Output format (`text`, `json`, or `sarif`)
* `-o`, `--output` (string): Output file path (stdout if not specified)
* `-c`, `--config` (string): Path to configuration file (`.depcheck.yaml`)
* `-v`, `--verbose`: Enable verbose logging
* `-h`, `--help`: Help for analyze command

### Examples

* Analyze a Node.js project and display output as a table:
  ```bash
  depcheck analyze -p ./my-node-project
  ```

* Analyze a .NET project and output results in JSON format:
  ```bash
  depcheck analyze -p ./my-dotnet-app -f json
  ```

* Analyze a Python project and output results in SARIF format to a file:
  ```bash
  depcheck analyze -p ./my-python-app -f sarif -o report.sarif
  ```

* Analyze a Maven project with a custom configuration file:
  ```bash
  depcheck analyze -p ./my-java-app -c custom-config.yaml
  ```

* Enable verbose logging for troubleshooting:
  ```bash
  depcheck analyze -p ./my-project -v
  ```

## Output Formats

### Text (Default)

The default text output provides a table summarizing the status of each dependency:

```
NAME                          CURRENT  LATEST     SEVERITY  COMPAT  DEPREC  NOTES
----                          -------  ------     --------  ------  ------  -----
django                        3.2      5.2.1      error     true    false   
requests                               2.32.3     info      true    false   
org.springframework:spring-core 5.3.10  6.1.3      error     false   false   Project version 5.3.10 is older than latest stable 6.1.3
com.fasterxml.jackson.core:jackson-databind 2.15.2 2.19.0  warning  false   false   Project version 2.15.2 is older than latest stable 2.19.0
nonexistent-package           1.0.0    not-found  error     false   false   Package not found in registry.
```

**Columns:**

* `NAME`: The name of the dependency package
* `CURRENT`: The version specified in your project's manifest file
* `LATEST`: The latest stable version found in the package registry
* `SEVERITY`: Indicates the urgency (`info`, `warning`, `error`)
* `COMPAT`: Compatibility status (based on analyzer logic)
* `DEPREC`: Indicates if the package is marked as deprecated or yanked
* `NOTES`: Additional context about the dependency status

### JSON

Using the `--format json` flag outputs the results as a JSON array of report items:

```json
[
  {
    "name": "django",
    "current_version": "3.2",
    "latest_version": "5.2.1",
    "deprecated": false,
    "compatible": false,
    "severity": "error",
    "notes": "Project version 3.2 is older than latest stable 5.2.1"
  },
  {
    "name": "requests",
    "current_version": "",
    "latest_version": "2.32.3",
    "deprecated": false,
    "compatible": true,
    "severity": "info",
    "notes": ""
  },
  {
    "name": "nonexistent-package-for-test",
    "current_version": "1.0.0",
    "latest_version": "not-found",
    "deprecated": false,
    "compatible": false,
    "severity": "error",
    "notes": "Package not found in registry."
  }
]
```

### SARIF

The SARIF (Static Analysis Results Interchange Format) output is designed for CI/CD integration:

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Dependency Checker",
          "version": "1.0.0",
          "informationUri": "https://github.com/sambabib/dependency-checker",
          "rules": [
            {
              "id": "outdated-major",
              "shortDescription": {
                "text": "Major version update available"
              },
              "fullDescription": {
                "text": "A major version update is available for this dependency, which may include breaking changes."
              },
              "help": {
                "text": "Consider updating with caution and review the changelog for breaking changes."
              }
            },
            // ... other rules ...
          ]
        }
      },
      "results": [
        {
          "ruleId": "outdated-major",
          "level": "warning",
          "message": {
            "text": "django: current version 3.2, latest version 5.2.1"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "requirements.txt"
                }
              }
            }
          ]
        },
        // ... other results ...
      ]
    }
  ]
}
```
## Configuration

The dependency checker supports configuration through a `.depcheck.yaml` file. You can place this file in your project directory or specify a custom path with the `-c` flag.

### Example Configuration

```yaml
# Exclude patterns for files or directories
exclude:
  - node_modules
  - vendor
  - .git

# Custom registries for different package managers
registries:
  npm: https://registry.npmjs.org
  nuget: https://api.nuget.org/v3/index.json
  maven: https://repo.maven.apache.org/maven2
  pypi: https://pypi.org/pypi

# Severity thresholds for reporting
severity:
  major: error    # Major version updates (potentially breaking changes)
  minor: warning  # Minor version updates (new features, non-breaking)
  patch: info     # Patch version updates (bug fixes)

# Output configuration
output:
  format: text    # Options: text, json, sarif
  file: ""        # Output file path (stdout if empty)

# Ignore specific packages
ignorePackages:
  - some-internal-package
  - legacy-package
```

## Supported Package Managers

### npm (Node.js)
- Parses `package.json` files
- Checks for outdated dependencies against npm registry
- Validates peer dependencies
- Handles version ranges and semver comparisons

### NuGet (.NET)
- Parses `.csproj` files
- Checks for outdated packages against NuGet Gallery
- Detects deprecated packages
- Validates framework compatibility

### Pip (Python)
- Parses `requirements.txt` files
- Checks for outdated packages against PyPI
- Handles pinned and unpinned dependencies
- Detects yanked versions

### Maven (Java)
- Parses `pom.xml` files
- Checks for outdated dependencies against Maven Central
- Resolves version properties (like `${project.version}`)
- Handles test and optional dependencies

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Check Dependencies

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  check-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Download Dependency Checker
        run: |
          curl -L https://github.com/sambabib/dependency-checker/releases/latest/download/depcheck-Linux-x86_64 -o depcheck
          chmod +x depcheck
      
      - name: Check Dependencies
        run: ./depcheck analyze -p . -f sarif -o dependency-report.sarif
      
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: dependency-report.sarif
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License

Copyright (c) 2025 samuraikitts

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
