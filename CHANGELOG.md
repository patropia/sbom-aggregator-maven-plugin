# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added
- Initial release of SBOM Aggregator Maven Plugin
- In-memory SBOM merging using CycloneDX Core Java library
- Hierarchical dependency tree construction
- Missing SBOM detection with fallback component generation
- Support for CycloneDX spec versions 1.3, 1.4, 1.5, 1.6, and 1.7
- Support for both JSON and XML output formats
- Configurable `failOnMissingSbom` option for strict builds
- Comprehensive integration test suite covering:
  - Simple aggregation scenarios
  - Multi-dependency projects with missing SBOMs
  - XML format support
  - Different spec versions
  - Build failure on missing SBOMs
- Unit tests with high code coverage
- CI/CD pipeline with GitHub Actions
- Maven Central deployment configuration

### Features
- **Automatic SBOM Resolution**: Resolves and aggregates SBOMs from all Maven dependencies
- **Fallback Components**: Creates placeholder components for dependencies without SBOMs
- **Flexible Configuration**: Supports multiple spec versions and output formats
- **Build Integration**: Seamlessly integrates into Maven build lifecycle
- **Comprehensive Logging**: Detailed warnings and summaries for missing SBOMs

### Documentation
- Complete README with usage examples
- Configuration parameter documentation
- Integration examples for upstream projects
- Contributing guidelines
- Apache 2.0 license

[1.0.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/releases/tag/v1.0.0
