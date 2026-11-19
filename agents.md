# Agent instructions for SBOM Aggregator Maven Plugin

This document is for contributors and agents working on the sbom-aggregator-maven-plugin repository. It documents the project layout, the responsibilities of the main classes, the current integration tests and the public configuration parameters.

Project structure (important files only):

- src/main/java/nl/patropia/maven/plugin/
  - AggregateSbomMojo.java       # Mojo: orchestrates dependency collection, SBOM resolution, merging and output
  - SbomMerger.java              # Pure merge logic: merges multiple CycloneDX Bom objects and synthesises placeholders
  - SpecValidation.java          # Spec version and output-format validation + helper conversions
- src/test/java/...              # Unit tests (AggregateSbomMojoTest, SbomMergerTest, SpecValidationTest)
- src/it/                        # Maven-Invoker integration tests (each folder is a standalone test)
- README.md                      # User-facing documentation (configuration table is authoritative)
- CHANGELOG.md                   # Release notes
- pom.xml                        # Build configuration and plugin coordinates

Core responsibilities

- AggregateSbomMojo: collects dependency coordinates (direct and optionally transitive), resolves attached SBOM artifacts, delegates parsing and merging to SbomMerger, writes output and optionally attaches it to the Maven project.
- SbomMerger: performs the in-memory merge and synthesises placeholder components for missing SBOMs. Keep merge-related unit tests here.
- SpecValidation: validate supported CycloneDX spec versions and the output extension.

Integration tests (invoker)

The integration tests are under src/it and use the Maven Invoker plugin. Each test folder contains a pom.xml, a setup.groovy (if needed) and verify.groovy. Current important tests:

- simple-integration-test
- attach-test
- transitive-test                # verifies transitive SBOM resolution + excludes behaviour
- transitive-disabled-test       # verifies behaviour when includeTransitive=false
(see src/it/ for the complete list)

Public configuration parameters (user properties)

The README.md is the authoritative source used by unit tests for parameter names. The plugin exposes the following configuration parameters, each of which can be set via the corresponding user property (-D):

- projectSbom                -> sbomAggregator.projectSbom (File)          Default: ${project.build.directory}/bom.json
- outputDirectory            -> sbomAggregator.outputDirectory (File)      Default: ${project.build.directory}
- dependencyClassifiers      -> sbomAggregator.dependencyClassifiers (List<String>) Default: ["cyclonedx"]
- dependencyExtensions       -> sbomAggregator.dependencyExtensions (List<String>)  Default: ["json","xml"]
- includeTransitive          -> sbomAggregator.includeTransitive (boolean)  Default: false
- includeScopes              -> sbomAggregator.includeScopes (List<String>) Default: [compile,runtime]
- excludes                   -> sbomAggregator.excludes (List<String>)     Default: (empty)
- outputClassifier           -> sbomAggregator.outputClassifier (String)   Default: cyclonedx
- outputExtension            -> sbomAggregator.outputExtension (String)    Default: json
- outputName                 -> sbomAggregator.outputName (String)         Default: aggregated-bom
- attach                     -> sbomAggregator.attach (boolean)             Default: true
- skip                       -> sbomAggregator.skip (boolean)               Default: false
- specVersion                -> sbomAggregator.specVersion (String)        Default: 1.5
- failOnMissingSbom          -> sbomAggregator.failOnMissingSbom (boolean) Default: false

Note: legacy parameter names sbomClassifier and sbomExtension were removed; do not use them.

Adding a new configuration parameter

1. Add an @Parameter field to AggregateSbomMojo.java with a property name beginning with sbomAggregator. For example: @Parameter(property = "sbomAggregator.myParam")
2. Update README.md's configuration table (unit tests read README.md to validate parameter names)
3. Add validation/usage code in the Mojo and add unit tests

Modifying merge logic

All SBOM merging and placeholder synthesis lives in SbomMerger.java and associated unit tests. To change the merging behaviour, edit SbomMerger and update SbomMergerTest.

Running tests

- Unit tests: mvn test
- Integration tests (invoker): mvn clean verify -Prun-its

Developer notes

- Output files are written under ${project.build.directory} by default. The plugin will attach the aggregated SBOM as an artifact with classifier outputClassifier and extension outputExtension unless attach=false.
- When adding or altering integration tests under src/it, ensure setup.groovy creates a file:// repository layout that matches Maven's groupId -> path conversion (dots become directories). A common pitfall is writing groupId paths with dots instead of directories.

Deprecated / removed items

- sbomClassifier and sbomExtension have been removed from the public configuration and the codebase; references were deleted. Marked as removed here and should not be reintroduced.

Contact / Help

If you are stuck, open an issue on GitHub or ping the maintainer via the repository issues page.

