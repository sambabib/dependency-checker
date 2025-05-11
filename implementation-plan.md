# Dependency Checker CLI - Implementation Plan

## 1. Project Initialization

- Create repository and Go module
  - `go mod init github.com/adekite/dependency-checker`
  - Add basic README, LICENSE, `.gitignore`
- Define CLI entrypoint
  - Use standard library `flag` or a framework (`spf13/cobra`)

## 2. Core Architecture

- `main.go`
  - Parse flags (project path, formats, verbosity)
  - Dispatch to appropriate analyzer (npm, NuGet, Maven, Pip)
- `pkg/analyzer`
  - Interface: `Analyze(path string) ([]ReportItem, error)`
  - Implementations per ecosystem:
    - npm/yarn: parse `package.json` + `package-lock.json` or `yarn.lock` (Implemented for package.json)
    - NuGet: parse `.csproj` or `packages.config` (Implemented for .csproj)
    - Maven: parse `pom.xml`
    - Pip: parse `requirements.txt` or `Pipfile`

## 3. Version and Deprecation Checks

- Query public registries:
  - npm registry API (Implemented)
  - NuGet V3 API (Implemented)
  - Maven Central
  - PyPI JSON API
- Determine latest stable and pre-release versions
- Detect deprecation metadata if available

## 4. Compatibility Analysis

- Compare installed versions vs. peer/peerDependencies
- Flag potential mismatches (e.g., required range not satisfied)
- (Future) Integrate community-maintained compatibility matrices

## 5. Reporting and Output

- Define `ReportItem` struct:
  - Name, current version, latest version, status (OK, outdated, deprecated), severity
- Output formats:
  - Plain text (console)
  - JSON (`--format json`)
  - SARIF for CI integration
- Logging: timestamps, verbose flag

## 6. Configuration and Overrides

- Support a config file (e.g. `.depcheck.yaml`)
  - Exclude lists, custom registries, severity thresholds
- Command-line flags for quick overrides

## 7. Testing

- Unit tests for:
  - Parsing manifest files
  - Registry client mocks
  - Report generation logic
  - NuGetAnalyzer (Comprehensive tests covering various scenarios implemented)
- Integration tests with sample projects

## 8. CI/CD Integration

- GitHub Actions workflow:
  - Run tests
  - On release: cross-compile binaries for Windows/macOS/Linux
  - Publish GitHub Releases

## 9. Documentation and Examples

- Expand README with usage examples
- Create sample projects in `examples/`
- Document configuration and output format

## 10. Roadmap and Future Enhancements

- Security vulnerability scan (GitHub Advisory, Snyk)
- License compliance checks
- Auto-update suggestions and one-click fixes
- Web dashboard or GitHub App integration
