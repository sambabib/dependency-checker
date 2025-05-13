# Dependency Checker CLI

A command-line tool to analyze project dependencies and report outdated, incompatible, or problematic packages.

## Features

*   Supports multiple project types:
    *   Node.js/npm (`package.json`)
    *   .NET/NuGet (`*.csproj`)
    *   Python/Pip (`requirements.txt`)
*   Checks for latest stable versions in respective package registries (npm registry, NuGet Gallery, PyPI).
*   Identifies outdated dependencies (major, minor, patch differences).
*   Reports deprecated packages (currently implemented for NuGet, potentially others).
*   Checks compatibility (primarily for npm peer dependencies and NuGet framework compatibility).
*   Provides severity levels (ok, info, warning, error) for each dependency.
*   Offers output in human-readable table format or JSON.

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd dependencychecker
    ```
2.  Build the executable:
    ```bash
    go build .
    ```
    This will create an executable named `dependency-checker` (or similar based on your module name) in the current directory.

## Usage

```bash
dependency-checker analyze -p <path-to-project> [flags]
```

**Arguments:**

*   `-p`, `--path` (string): Path to the project directory to analyze (required).

**Flags:**

*   `-f`, `--format` (string): Output format ('text' or 'json') (default "text").
*   `-h`, `--help`: Help for analyze command.

**Examples:**

*   Analyze a project and display output as a table:
    ```bash
    ./dependency-checker analyze -p ./my-node-project
    ```
*   Analyze a project and output results in JSON format:
    ```bash
    ./dependency-checker analyze -p /path/to/my-dotnet-app -f json
    ```

## Output Format

### Text (Default)

The default text output provides a table summarizing the status of each dependency:

```
NAME                          CURRENT  LATEST     SEVERITY  COMPAT  DEPREC  NOTES
----                          -------  ------     --------  ------  ------  -----
django                        3.2      5.2.1      error     true    false
requests                               2.32.3     info      true    false
nonexistent-package-for-test  1.0.0    not-found  error     true    false   Package not found in registry.
```

**Columns:**

*   `NAME`: The name of the dependency package.
*   `CURRENT`: The version specified in your project's manifest file.
*   `LATEST`: The latest stable version found in the package registry.
*   `SEVERITY`: Indicates the urgency (`ok`, `info`, `warning`, `error`).
*   `COMPAT`: Compatibility status. 
    *   **For npm/NuGet:** Primarily indicates peer/framework dependency compatibility (based on analyzer logic).
    *   **For Pip:** This is currently always `true`, as complex compatibility checks like peer dependencies are not performed for Python packages in this tool.
*   `DEPREC`: Indicates if the package version is marked as deprecated or yanked (`true`/`false`).
*   `NOTES`: Provides additional context, such as yanked reasons, specific errors encountered during analysis (e.g., package not found, registry errors), or why a stable version couldn't be determined.

### JSON

Using the `--format json` flag outputs the results as a JSON array of report items:

```json
[
  {
    "name": "django",
    "current_version": "3.2",
    "latest_version": "5.2.1",
    "deprecated": false,
    "compatible": true,
    "severity": "error",
    "notes": ""
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
    "compatible": true,
    "severity": "error",
    "notes": "Package not found in registry."
  }
]
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

(Specify your license here, e.g., MIT License)
