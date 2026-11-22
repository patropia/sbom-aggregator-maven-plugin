# Contributing to SBOM Aggregator Maven Plugin

Thank you for your interest in contributing to the SBOM Aggregator Maven Plugin! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Your environment (Java version, Maven version, OS)
- Any relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please create an issue with:

- A clear description of the feature
- The use case and benefits
- Any implementation ideas you have

### Pull Requests

1. **Fork the repository** and create a new branch from `main`
2. **Make your changes** following the coding standards below
3. **Add tests** for any new functionality
4. **Update documentation** (README.md, CHANGELOG.md, etc.)
5. **Ensure all tests pass**: `mvn clean verify -Prun-its`
6. **Commit your changes** with clear, descriptive commit messages
7. **Push to your fork** and submit a pull request

## Development Setup

### Prerequisites

- Java 17 or higher
- Maven 3.9.x or higher
- Git

### Building the Project

```bash
# Clone the repository
git clone https://github.com/patropia/sbom-aggregator-maven-plugin.git
cd sbom-aggregator-maven-plugin

# Build and run tests
mvn clean verify

# Run integration tests
mvn clean install -Prun-its

# Install locally for testing
mvn clean install
```

### Running Tests

```bash
# Unit tests only
mvn test

# All tests including integration tests
mvn clean verify -Prun-its
```

### Testing Your Changes Locally

After installing the plugin locally with `mvn clean install`, you can test it in another project:

```xml
<plugin>
    <groupId>nl.patropia.maven.plugin</groupId>
    <artifactId>sbom-aggregator-maven-plugin</artifactId>
    <version>1.2.0-SNAPSHOT</version>
    <executions>
        <execution>
            <phase>verify</phase>
            <goals>
                <goal>aggregate-sboms</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

## Coding Standards

### Java Code Style

- Use 4 spaces for indentation (no tabs)
- Follow standard Java naming conventions
- Keep methods focused and concise
- Add Javadoc comments for public APIs
- Use meaningful variable and method names

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or modifications
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: add support for SPDX format
fix: resolve NPE when dependency has no version
docs: update README with new configuration options
test: add integration test for XML format
refactor: simplify SBOM merging logic
chore: update dependencies to latest versions
```

### Documentation

- Update README.md for user-facing changes
- Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/) format
- Add Javadoc for new public methods and classes
- Update integration test documentation if needed

## Project Structure

```
sbom-aggregator-maven-plugin/
├── src/
│   ├── main/
│   │   └── java/
│   │       └── nl/patropia/maven/plugin/
│   │           └── AggregateSbomMojo.java    # Main plugin implementation
│   ├── test/
│   │   └── java/                              # Unit tests
│   └── it/                                    # Integration tests
│       ├── simple-integration-test/
│       ├── multi-dependency-test/
│       ├── multi-classifier-test/
│       ├── fail-on-missing-test/
│       ├── spec-version-test/
│       └── xml-format-test/
├── .github/
│   └── workflows/                             # CI/CD workflows
├── pom.xml                                    # Maven configuration
├── README.md                                  # User documentation
├── CHANGELOG.md                               # Version history
├── CONTRIBUTING.md                            # This file
└── LICENSE                                    # Apache 2.0 license
```

## Adding Integration Tests

Integration tests are located in `src/it/`. To add a new test:

1. Create a new directory: `src/it/your-test-name/`
2. Add a `pom.xml` with the test project configuration
3. Add a `src/sbom/base-bom.json` (or `.xml`) with test SBOM
4. Add `setup.groovy` for pre-test setup (optional)
5. Add `verify.groovy` to verify test results
6. Add `invoker.properties` with test configuration

Example `verify.groovy`:
```groovy
def aggregatedBom = new File(basedir, "target/aggregated-bom.json")
assert aggregatedBom.exists() : "Aggregated SBOM should exist"
assert aggregatedBom.length() > 0 : "Aggregated SBOM should not be empty"
println "✓ Test passed"
return true
```

## Release Process

Only maintainers can create releases. The process is documented in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/patropia/sbom-aggregator-maven-plugin/issues)
- **Discussions**: [GitHub Discussions](https://github.com/patropia/sbom-aggregator-maven-plugin/discussions)

## License

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0.
