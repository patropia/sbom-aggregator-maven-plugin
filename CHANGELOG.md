# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (BREAKING)
- Command-line user properties are now required to use the `sbomAggregator.*` prefix. Bare `-D` property names such as `-DspecVersion=...` or `-DprojectSbom=...` are no longer honoured by the plugin.

### Added
- Integration test `transitive-test` verifying transitive SBOM resolution, scope filtering and excludes.
- New transitive-resolution options: `includeTransitive`, `includeScopes`, and `excludes`.
- Configuration parameters: `attach`, `skip`, and `outputName`.

### Other changes
- Publishing moved from OSSRH/Nexus staging to the Sonatype Central Portal
  (`central-publishing-maven-plugin`); release secrets are now
  `CENTRAL_TOKEN_USERNAME`/`CENTRAL_TOKEN_PASSWORD`.
- Build now requires Maven >= 3.6.3 and Java >= 17 (enforced by
  `maven-enforcer-plugin`); the compiler uses `maven.compiler.release=17`,
  so builds on older toolchains fail fast instead of half-working.

## [1.0.0] - 2026-10-14

### Added
- Initial release of SBOM Aggregator Maven Plugin
- In-memory SBOM merging using CycloneDX Core Java library (v13.2.0)
- Hierarchical dependency tree construction with root component metadata
- Missing SBOM detection with fallback component generation
- Support for CycloneDX spec versions 1.3, 1.4, 1.5, 1.6, and 1.7
- Support for both JSON and XML input and output formats
- Multiple classifier support for resolving dependent SBOMs (`dependencyClassifiers`)
- Multiple extension support for resolving dependent SBOMs (`dependencyExtensions`)
- Configurable output format and classifier (`outputExtension`, `outputClassifier`)
- Configurable `failOnMissingSbom` option for strict builds
- Comprehensive integration test suite:
  - Simple aggregation scenarios
  - Multi-dependency projects with missing SBOMs
  - Multi-classifier resolution testing
  - XML format support
  - Different spec versions
  - Build failure on missing SBOMs
- Unit tests with high code coverage
- CI/CD pipeline with GitHub Actions for automated testing
- Maven Central deployment configuration with GPG signing
- Automated release workflow via GitHub Actions

### Features
- **Automatic SBOM Resolution**: Resolves and aggregates SBOMs from all Maven dependencies using configurable classifiers and extensions
- **Fallback Components**: Creates placeholder components for dependencies without SBOMs to maintain complete supply chain visibility
- **Flexible Configuration**: Supports multiple spec versions, output formats, and dependency resolution strategies
- **Build Integration**: Seamlessly integrates into Maven build lifecycle (typically `verify` phase)
- **Optimized Logging**: Clean, concise build output with debug-level details available when needed
- **Multi-Repository Support**: Designed for large multi-repository software projects with cross-repo SBOM aggregation

### Configuration Parameters
- `projectSbom`: Path to base project SBOM
- `outputDirectory`: Directory for aggregated SBOM output
- `dependencyClassifiers`: List of classifiers to try when resolving dependency SBOMs
- `dependencyExtensions`: List of extensions to try when resolving dependency SBOMs
- `outputClassifier`: Classifier for the output aggregated SBOM
- `outputExtension`: Format for the output aggregated SBOM (json/xml)
- `specVersion`: Target CycloneDX specification version
- `failOnMissingSbom`: Whether to fail build on missing dependency SBOMs

### Documentation
- Complete README with usage examples and quick start guide
- Detailed configuration parameter documentation
- Integration examples for upstream projects
- Dependency resolution configuration examples
- Output format customization examples
- Release process documentation
- Contributing guidelines
- Apache 2.0 license

### Technical Details
- Requires Java 17 or higher
- Requires Maven 3.9.x or higher
- Uses Eclipse Aether for artifact resolution
- Powered by CycloneDX Core Java library for SBOM parsing and generation

[1.0.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/releases/tag/v1.0.0
