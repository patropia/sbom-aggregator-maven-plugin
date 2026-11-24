# Agent instructions for SBOM Aggregator Maven Plugin

This document is for contributors and agents working on the sbom-aggregator-maven-plugin repository. It documents the project layout, the responsibilities of the main classes, the current integration tests and the public configuration parameters.

Project structure (important files only):

- src/main/java/nl/patropia/maven/plugin/
  - AggregateSbomMojo.java       # Mojo: orchestrates dependency collection, SBOM resolution, merging and output
  - SbomMerger.java              # Pure merge logic: merges multiple CycloneDX Bom objects and synthesises placeholders
  - SpecValidation.java          # Spec version and output-format validation + helper conversions
- src/test/java/...              # Unit tests (AggregateSbomMojoTest, AggregateSbomMojoAttachTest,
                                 # ParameterPropertyNamingTest, SbomMergerTest, SpecValidationTest)
- src/it/                        # Maven-Invoker integration tests (each folder is a standalone test)
- README.md                      # User-facing documentation (configuration table is authoritative)
- CHANGELOG.md                   # Release notes
- pom.xml                        # Build configuration and plugin coordinates

Core responsibilities

- AggregateSbomMojo: collects dependency coordinates (direct and optionally transitive), resolves attached SBOM artifacts, delegates parsing and merging to SbomMerger, writes output and optionally attaches it to the Maven project.
- SbomMerger: performs the in-memory merge and synthesises placeholder components for missing SBOMs. Keep merge-related unit tests here.
- SpecValidation: validate supported CycloneDX spec versions and the output extension.

Integration tests (invoker)

The integration tests are under src/it and use the Maven Invoker plugin. Each test folder contains a pom.xml, a setup.groovy (if needed) and verify.groovy. Shared files:

- setup.groovy                   # shared setup script (creates the file:// test repository)
- invoker-settings.xml           # Maven settings used by the invoker runs

The test folders are:

- fail-on-missing-test           # failOnMissingSbom=true fails the build
- invalid-sbom-test              # an invalid input SBOM fails the build
- multi-classifier-test          # several dependency classifiers
- multi-dependency-test          # multiple dependencies, missing SBOM placeholders
- reproducible-test              # output is identical between builds
- simple-integration-test        # baseline aggregation
- spec-version-test              # spec version selection
- transitive-test                # transitive SBOM resolution, includes/excludes and scopes
- transitive-disabled-test       # behaviour when includeTransitive=false (default)
- vulnerability-merge-test       # vulnerabilities merged, duplicates unioned, affects refs resolve to components
- vulnerability-multi-sbom-test  # several dependency SBOMs sharing a component bom-ref; affects refs follow renamed components
- xml-format-test                # XML output format

Public configuration parameters (user properties)

The README.md is the authoritative source used by unit tests for parameter names. The plugin exposes the following configuration parameters, each of which can be set via the corresponding user property (-D):

- projectSbom                -> sbomAggregator.projectSbom (File)          Default: ${project.build.directory}/bom.json
- outputDirectory            -> sbomAggregator.outputDirectory (File)      Default: ${project.build.directory}
- dependencyClassifiers      -> sbomAggregator.dependencyClassifiers (List<String>) Default: ["cyclonedx"]
- dependencyExtensions       -> sbomAggregator.dependencyExtensions (List<String>)  Default: ["json","xml"]
- includeTransitive          -> sbomAggregator.includeTransitive (boolean)  Default: false
- includeVulnerabilities     -> sbomAggregator.includeVulnerabilities (boolean) Default: true (merge vulnerabilities, spec 1.4+)
- includeScopes              -> sbomAggregator.includeScopes (List<String>) Default: [compile,runtime]
- excludes                   -> sbomAggregator.excludes (List<String>)     Default: (empty)
- outputClassifier           -> sbomAggregator.outputClassifier (String)   Default: cyclonedx
- outputExtension            -> sbomAggregator.outputExtension (String)    Default: json
- outputName                 -> sbomAggregator.outputName (String)         Default: aggregated-bom
- attach                     -> sbomAggregator.attach (boolean)             Default: true
- skip                       -> sbomAggregator.skip (boolean)               Default: false
- specVersion                -> sbomAggregator.specVersion (String)        Default: 1.7
- outputTimestamp            -> sbomAggregator.outputTimestamp (String)    Default: ${project.build.outputTimestamp}
- maxSbomSize                -> sbomAggregator.maxSbomSize (String)        Default: 50MB (bytes or KB/MB/GB; 0 = unlimited)
- failOnInvalidSbom          -> sbomAggregator.failOnInvalidSbom (boolean) Default: true
- failOnMissingSbom          -> sbomAggregator.failOnMissingSbom (boolean) Default: false

Notes:

- Only the `sbomAggregator.*` user properties are honoured on the command line; bare `-D` names (for example `-DspecVersion=1.6`) are ignored.
- `failOnMissingSbom` applies to every collected dependency: the direct ones, plus the transitive ones when `includeTransitive=true`. It is evaluated after parsing, so a dependency SBOM downgraded to missing by `failOnInvalidSbom=false` also counts.
- Input SBOMs are read by SbomInputReader: JSON/XML is detected from the content (not the file extension), files above `maxSbomSize` are rejected and parse errors never echo file contents.
- Legacy parameter names `sbomClassifier` and `sbomExtension` no longer exist; do not use them.

Adding a new configuration parameter

1. Add an @Parameter field to AggregateSbomMojo.java with a property name beginning with sbomAggregator. For example: @Parameter(property = "sbomAggregator.myParam") (parameters of the diff-sboms goal live in DiffSbomMojo.java and use the sbomAggregator.diff.* prefix)
2. Update README.md's configuration table (unit tests read README.md to validate parameter names)
3. Update ParameterPropertyNamingTest: it holds the expected parameter/property set and will fail until the new parameter is added there
4. Add validation/usage code in the Mojo and add unit tests

SBOM diff

The diff-sboms goal (DiffSbomMojo) reads two SBOMs with SbomInputReader and delegates to the pure SbomDiff logic, which returns an SbomDiffReport. Report rendering (JSON/Markdown, including escaping of untrusted values) lives in DiffSbomMojo; tests are SbomDiffTest, DiffSbomMojoTest and the ITs src/it/diff-test and src/it/diff-fail-test.
When current is not configured, DiffSbomMojo.currentSbom() resolves ${project.build.directory}/<outputName>.<outputExtension>, sharing the sbomAggregator.outputName/outputExtension properties with aggregate-sboms.
currentSbom() does not follow AggregateSbomMojo's outputDirectory; users with a custom sbomAggregator.outputDirectory must set sbomAggregator.diff.current. ParameterPropertyNamingTest checks both goals: diff parameters use sbomAggregator.diff.*, except the shared outputName/outputExtension/maxSbomSize (sbomAggregator.*); the read-only buildDirectory is skipped.

SPDX conversion

SpdxConverter is a pure, package-private utility (no Maven API) that converts a CycloneDX Bom into an SPDX 2.3 JSON document: components (nested ones hoisted, the metadata root de-duplicated by bom-ref) become packages; the document DESCRIBES the root, nesting becomes CONTAINS and CycloneDX dependencies become DEPENDS_ON (self-loops, unknown refs and duplicates dropped). Hashes map to checksums (algorithms without an SPDX equivalent, e.g. Streebog, are dropped), licences to licenseDeclared (names become LicenseRef-* with hasExtractedLicensingInfos), purl/CPE to externalRefs. Vulnerabilities, services and compositions have no SPDX 2.3 equivalent and are not converted (the creationInfo comment says so). Pass a fixed Instant to toJson/toSpdx for byte-identical, reproducible output. Tests: SpdxConverterTest.
aggregate-sboms exposes this via generateSpdx (sbomAggregator.generateSpdx, default false): AggregateSbomMojo.writeSpdxOutput writes <outputDirectory>/<outputName>.spdx.json using the parsed outputTimestamp and attaches it as classifier spdx / type json when attach=true. validateConfiguration rejects outputClassifier=spdx with outputExtension=json in that case (the artifacts would clash). Compound licence expressions are bracketed when AND-joined. Tests: AggregateSbomMojoAttachTest, IT src/it/spdx-output-test.
documentNamespace hashes the document name, timestamp and a content digest of the rendered packages (id, name, version, supplier, checksums, licences, external refs) plus the relationships (Builder.contentDigest), so it is unique per content yet reproducible. licenseRefFor suffixes colliding LicenseRef slugs with -2, -3, … and always maps the same licence name to the same id.

Modifying merge logic

All SBOM merging and placeholder synthesis lives in SbomMerger.java and associated unit tests. To change the merging behaviour, edit SbomMerger and update SbomMergerTest.

Java baseline

- Java 11 is the minimum supported version: pom.xml sets maven.compiler.release=11 and maven-enforcer-plugin requires [11,).
- Main and test code must compile on Java 11: do not use text blocks, records, Stream.toList(), switch expressions or pattern-matching instanceof. Put larger test fixtures (e.g. JSON) under src/test/resources instead of text blocks.
- JUnit stays on 5.x because JUnit 6 requires Java 17; Dependabot is configured to ignore major JUnit updates.
- ReleaseHygieneTest.javaBaselineStaysAtJava11 enforces the baseline (pom.xml release/enforcer and the src/it poms); CI builds on JDK 11, 17 and 21.

Running tests

- Unit tests: mvn test
- Integration tests (invoker): mvn clean verify -Prun-its

Developer notes

- Output files are written under ${project.build.directory} by default. The plugin will attach the aggregated SBOM as an artifact with classifier outputClassifier and extension outputExtension unless attach=false.
- When adding or altering integration tests under src/it, ensure setup.groovy creates a file:// repository layout that matches Maven's groupId -> path conversion (dots become directories). A common pitfall is writing groupId paths with dots instead of directories.

Removed items (ready for deletion)

The project has no external users yet, so nothing is kept for backwards compatibility: removed API or configuration is deleted outright rather than deprecated.

- sbomClassifier and sbomExtension: already deleted from the configuration and the codebase. Any re-appearing reference should be deleted, not deprecated.
- Old `-D` property names without the `sbomAggregator.` prefix: already deleted; no compatibility shims.

Contact / Help

If you are stuck, open an issue on GitHub or ping the maintainer via the repository issues page.

