# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Components are now matched on a canonical purl key (lowercased type, consistent percent-encoding, sorted
  qualifiers, Maven `type=jar` ignored while `classifier` is kept), so a jar found by a scanner such as Syft or
  Trivy (`pkg:maven/...?type=jar`, no `group`) merges with the Maven dependency component instead of being
  duplicated. A missing `group` is derived from the Maven purl namespace. rpm/deb arch and distro variants stay
  separate.

## [1.3.0] - 2026-11-23

### Added
- New `diff-sboms` goal (default phase `verify`): compares a baseline SBOM with the current (aggregated) SBOM and
  writes deterministic `sbom-diff.json` / `sbom-diff.md` reports of added, removed, upgraded/downgraded components
  and new/resolved vulnerabilities. `sbomAggregator.diff.failOnNewVulnerabilities=true` fails the build on new
  vulnerabilities. Markdown output escapes untrusted SBOM values.
  When `sbomAggregator.diff.current` is not set, the current SBOM defaults to
  `${project.build.directory}/<outputName>.<outputExtension>`, so custom output names and XML output work.
- Internal SPDX 2.3 JSON converter (`SpdxConverter`) mapping CycloneDX components, nesting, dependencies, hashes,
  licences, purl/CPE references and download locations to SPDX packages and relationships, with reproducible output
  for a fixed timestamp (groundwork for SPDX output of `aggregate-sboms`).
- `jackson-databind` is now a declared (direct) dependency instead of arriving transitively via cyclonedx-core-java.
- SPDX output for `aggregate-sboms`: `generateSpdx=true` (`-DsbomAggregator.generateSpdx=true`) also writes
  `<outputName>.spdx.json` (SPDX 2.3 JSON) and, when `attach=true`, attaches it with classifier `spdx`. The document
  is reproducible when `outputTimestamp` is set. `outputClassifier=spdx` with JSON output is rejected when SPDX is
  attached, because the two artifacts would clash.
- README documents that `diff-sboms` reads the current SBOM from `${project.build.directory}` and does not follow a
  custom `sbomAggregator.outputDirectory`; set `sbomAggregator.diff.current` in that case.

### Fixed
- SPDX conversion brackets compound licence expressions when a component has several licences, so
  `MIT OR Apache-2.0` plus `BSD-3-Clause` becomes `(MIT OR Apache-2.0) AND BSD-3-Clause` instead of changing meaning.
- SPDX `documentNamespace` now also hashes the generated package payload (id, name, version, supplier, checksums,
  licences) and relationships, so two documents that share a name and timestamp but differ in content get distinct
  namespaces (output stays reproducible for the same BOM).
- Distinct licence names that sanitise to the same `LicenseRef-*` id (e.g. `MIT License` / `MIT/License`) now get
  their own ids (`-2`, `-3`, …) instead of silently sharing the first name's extracted licence text.

## [1.2.0] - 2026-11-23

### Added
- Vulnerability correlation: the `vulnerabilities` sections of all input SBOMs are merged into the aggregated BOM
  (spec 1.4+). Entries with the same id and source are de-duplicated with their `affects` lists unioned, `affects`
  refs are rewritten to the final (collision-safe) component bom-refs, and refs to unknown components are dropped.
  Output is sorted for reproducible builds. Disable with `includeVulnerabilities=false`
  (`-DsbomAggregator.includeVulnerabilities=false`).

### Changed
- Minimum Java version lowered from 17 to 11: the plugin is now compiled to Java 11 bytecode
  (`maven.compiler.release=11`) and the enforcer rule requires Java `[11,)`.
- CI now builds and tests on JDK 11, 17 and 21.
- Test dependency moved from JUnit 6.1.3 back to JUnit 5.14.x, because JUnit 6 requires Java 17.
- Build dependency `maven.version` bumped from 3.9.6 to 3.9.16 (PR #30).

### Fixed
- Build no longer fails after the post-release bump to the next `-SNAPSHOT`: the release-hygiene tests now accept
  README and issue-template examples that reference the latest published release (from CHANGELOG.md) while on a
  development snapshot. Release builds still require the examples to match the version being released.

## [1.1.0] - 2026-11-22

> **Versioning note:** this release contains one breaking change (the
> `sbomAggregator.*` property prefix below) but is deliberately published as a
> minor version. 1.0.0 was tagged in git but never published to Maven Central,
> so no Central consumer can be affected. From 1.1.0 onwards, breaking changes
> will bump the major version as Semantic Versioning requires.

### Changed (BREAKING)
- Command-line user properties are now required to use the `sbomAggregator.*` prefix. Bare `-D` property names such as `-DspecVersion=...` or `-DprojectSbom=...` are no longer honoured by the plugin.
  - **Migration:** prefix every command-line property, e.g. `-DspecVersion=1.6` becomes `-DsbomAggregator.specVersion=1.6` and `-DprojectSbom=...` becomes `-DsbomAggregator.projectSbom=...`. Values configured in the plugin's `<configuration>` block are unaffected.

### Added
- New transitive-resolution options: `includeTransitive`, `includeScopes`, and `excludes`.
- Configuration parameters: `attach`, `skip`, `outputName`, and `outputTimestamp`.
- **Reproducible builds:** `outputTimestamp` accepts an ISO-8601 instant or epoch seconds (typically
  `${project.build.outputTimestamp}`). When it is set, the aggregated SBOM uses that fixed `metadata.timestamp` and a
  name-based `urn:uuid` `serialNumber`, so two builds of the same inputs produce byte-identical SBOMs.
- **Input hardening:** new `maxSbomSize` (default `50MB`, accepts `KB`/`MB`/`GB`, `0` = unlimited) rejects oversized
  input SBOMs before they are parsed, and input format is now detected from the file content instead of the file
  extension. Parse failures report only the file and the parser exception class, never the file contents.
- **Input validation:** new `failOnInvalidSbom` (default `true`). When `false`, a dependency SBOM that is not valid
  CycloneDX JSON/XML or exceeds `maxSbomSize` is reported as missing and gets a placeholder component instead of
  failing the build. An invalid project SBOM always fails the build.
- **Output validation:** new `validateOutput` (default `true`) validates the generated SBOM against the bundled
  CycloneDX JSON/XML schema of the configured `specVersion` before the file is written; on failure the build fails
  and no output file is produced. Validation is offline and can be disabled with
  `-DsbomAggregator.validateOutput=false`. Only the first schema problem is shown in the error message (the message can
  quote values from the generated SBOM); with `-X` every problem is logged at debug level.
- **Aggregated document metadata:** the aggregated SBOM now carries a `urn:uuid` `serialNumber` (deterministic when
  `outputTimestamp` is set), a `metadata.timestamp` and a `metadata.tools` entry for this plugin
  (`tools.components` for spec 1.5+, the legacy `tools[]` array for 1.3/1.4).
- **Merged content:** `services` from input SBOMs are merged (bom-ref/GAV de-duplication with collision-safe ref
  renaming); `compositions` are emitted for spec >= 1.4 (`unknown` for placeholders, `incomplete` for the root);
  the root `metadata.component` is enriched from the project's own SBOM (description, licenses, supplier, hashes,
  external references) and metadata licenses/supplier/manufacturer are carried over. Placeholder components carry
  the property `sbomAggregator:missingSbom=true`.
- Integration test `transitive-test` verifying transitive SBOM resolution, scope filtering and excludes.
- Integration test `transitive-disabled-test` verifying the default `includeTransitive=false` behaviour.
- Integration test `invalid-sbom-test` verifying that an invalid dependency SBOM fails the build without writing an
  output file and without leaking the file contents into the build log.
- Integration test `reproducible-test` verifying that two runs with the same `outputTimestamp` produce the same
  `serialNumber`, `metadata.timestamp` and component order.

### Changed
- `failOnMissingSbom` is now evaluated after the input SBOMs are parsed, so a dependency SBOM that was downgraded to
  missing by `failOnInvalidSbom=false` also fails the build when `failOnMissingSbom=true`.

### Fixed
- **Purls:** Maven purls are now built by a dedicated helper that percent-encodes namespace, name, version and
  qualifier values and orders `classifier`/`type` qualifiers alphabetically, as the purl specification requires.

### Other changes
- Publishing moved from OSSRH/Nexus staging to the Sonatype Central Portal
  (`central-publishing-maven-plugin`); release secrets are now
  `CENTRAL_TOKEN_USERNAME`/`CENTRAL_TOKEN_PASSWORD`.
- Build now requires Maven >= 3.6.3 and Java >= 17 (enforced by
  `maven-enforcer-plugin`); the compiler uses `maven.compiler.release=17`,
  so builds on older toolchains fail fast instead of half-working.
- The obsolete `org.eclipse.aether:aether-api:1.1.0` dependency was replaced by
  `org.apache.maven.resolver:maven-resolver-api` 1.9.27 (`provided` scope). The
  `org.eclipse.aether.*` package names are unchanged, so no plugin configuration
  or user-facing behaviour is affected. The 2.x resolver line is intentionally not
  used because it targets Maven 4.
- Build plugin bumps: `maven-plugin-plugin` and `maven-plugin-annotations` 3.15.2,
  `maven-invoker-plugin` 3.9.1, `central-publishing-maven-plugin` 0.8.0.
- CI now builds and runs the integration tests on Java 17 and Java 21. CodeQL
  code scanning (weekly plus on every push/PR) and Dependabot updates for Maven
  dependencies and GitHub Actions were added.
- SCM metadata moved to `scm:git:https://…` for the connection and a valid
  `scm:git:ssh://git@github.com/…` developer connection, and `<issueManagement>`
  was added so IDEs and the Central Portal can link to the issue tracker.
- Added `SECURITY.md` (private vulnerability reporting through GitHub security
  advisories) and `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- Release workflow hardening: `softprops/action-gh-release@v2`, a `concurrency`
  group that never cancels an in-flight release, Maven batch mode (`-B -ntp`),
  `permissions: contents: write` only, the tag version passed to `versions:set`
  through an environment variable instead of being interpolated into the shell
  command, and exactly one build/deploy/release sequence.
- New `ReleaseHygieneTest` unit tests pin the items above (dependency scopes,
  resolver coordinates, SCM URLs, CI matrix, CodeQL/Dependabot configuration,
  community files and a single deploy/release step) so they cannot silently
  regress.

### Dependencies
- Test dependencies: JUnit Jupiter 5.10.2 → 6.1.3, JaCoCo 0.8.12 → 0.8.16.
- Build plugins: compiler 3.16.0, surefire 3.6.1, jar 3.5.1, source 3.4.0,
  javadoc 3.12.0, invoker 3.10.1, gpg 3.2.8, enforcer 3.7.0,
  plugin-tools 3.16.0 and central-publishing 0.12.0.
- Maven Resolver stays on 1.9.27 and the Maven API on 3.9.6 so that the plugin
  keeps matching the API that Maven 3.9 provides at runtime; Dependabot now
  ignores resolver major updates and Maven API minor/major updates.

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

[Unreleased]: https://github.com/patropia/sbom-aggregator-maven-plugin/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/patropia/sbom-aggregator-maven-plugin/releases/tag/v1.0.0
