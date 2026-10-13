# Agent Instructions for SBOM Aggregator Maven Plugin

## Project Overview

This is a Maven plugin that aggregates CycloneDX Software Bill of Materials (SBOMs) from dependent projects. It's designed for Software Composition Analysis (SCA) in large multi-repository software projects.

**Key Technologies:**
- Java 17+
- Maven 3.9.x+
- CycloneDX Core Java library
- Maven Plugin API

## Project Structure

```
sbom-aggregator-maven-plugin/
├── src/
│   ├── main/java/nl/patropia/maven/plugin/
│   │   └── AggregateSbomMojo.java          # Main plugin implementation
│   ├── test/java/nl/patropia/maven/plugin/
│   │   └── AggregateSbomMojoTest.java      # Unit tests
│   └── it/                                  # Integration tests
│       ├── invoker-settings.xml
│       └── simple-integration-test/
│           ├── pom.xml
│           ├── invoker.properties
│           ├── verify.groovy
│           └── src/sbom/base-bom.json
├── pom.xml                                  # Project build configuration
└── README.md                                # User documentation
```

## Core Functionality

The plugin performs these operations:
1. Reads a base project SBOM (CycloneDX format)
2. Resolves SBOMs from all Maven dependencies
3. Merges them in-memory using `cyclonedx-core-java`
4. Builds a hierarchical dependency tree
5. Detects missing SBOMs and creates placeholder components
6. Outputs an aggregated SBOM in the specified CycloneDX version

## Development Commands

**Build and test:**
```bash
mvn clean verify -Prun-its
```

**Run unit tests only:**
```bash
mvn test
```

**Install locally:**
```bash
mvn clean install
```

## Configuration Parameters

When editing `AggregateSbomMojo.java`, be aware of these configurable parameters:

- `projectSbom` (File): Path to base SBOM, default: `${project.build.directory}/bom.json`
- `outputDirectory` (File): Output directory, default: `${project.build.directory}`
- `sbomClassifier` (String): Artifact classifier, default: `cyclonedx`
- `sbomExtension` (String): File format, default: `json`
- `specVersion` (String): CycloneDX spec version, default: `1.5` (supports 1.3-1.7)
- `failOnMissingSbom` (boolean): Fail build on missing SBOM, default: `false`

## Code Conventions

- **Language Level:** Java 17
- **Maven Annotations:** Use `@Mojo`, `@Parameter`, `@Component` annotations
- **Logging:** Use Maven's `getLog()` for info, warn, error messages
- **Error Handling:** Throw `MojoExecutionException` for execution failures, `MojoFailureException` for validation failures
- **Testing:** Use JUnit for unit tests, Maven Invoker for integration tests

## Key Dependencies

- `org.cyclonedx:cyclonedx-core-java` - SBOM parsing and merging
- `org.apache.maven:maven-plugin-api` - Maven plugin framework
- `org.apache.maven:maven-core` - Maven project model
- `org.apache.maven.plugin-tools:maven-plugin-annotations` - Plugin metadata

## Integration Testing

Integration tests use Maven Invoker Plugin:
- Located in `src/it/`
- Each test has its own `pom.xml` and `verify.groovy` script
- Run with `-Prun-its` profile
- Tests verify the plugin works in real Maven builds

## Common Tasks

**Adding a new configuration parameter:**
1. Add `@Parameter` annotated field to `AggregateSbomMojo.java`
2. Update README.md configuration table
3. Add validation logic in `execute()` method
4. Add unit test coverage

**Modifying SBOM merging logic:**
1. Edit the merge logic in `AggregateSbomMojo.java`
2. Update unit tests in `AggregateSbomMojoTest.java`
3. Add/update integration test if behavior changes
4. Test with `mvn clean verify -Prun-its`

**Supporting a new CycloneDX version:**
1. Update `specVersion` parameter validation
2. Test with new version in integration tests
3. Update README.md supported versions list

## Important Notes

- The plugin uses in-memory merging (no external CLI tools)
- Missing SBOMs generate warnings and placeholder components
- Hierarchical dependency tree is maintained in the output
- Output format matches the specified CycloneDX spec version
- Direct dependencies without SBOMs can optionally fail the build

## Upstream Integration

For this plugin to work, upstream projects must attach their SBOMs using:
```xml
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <configuration>
        <attach>true</attach>
    </configuration>
</plugin>
```

## Deployment

The project is configured for deployment to Maven Central via GitHub Actions.

**Release Process:**
1. Update version in `pom.xml` (remove `-SNAPSHOT`)
2. Update `CHANGELOG.md` with release notes
3. Create and push a git tag: `git tag -a v1.0.0 -m "Release 1.0.0" && git push origin v1.0.0`
4. GitHub Actions will automatically build, test, sign, and deploy to Maven Central
5. After release, bump version to next `-SNAPSHOT` version

**Required GitHub Secrets:**
- `OSSRH_USERNAME` - Sonatype OSSRH username
- `OSSRH_TOKEN` - Sonatype OSSRH token
- `GPG_PRIVATE_KEY` - Base64-encoded GPG private key
- `GPG_PASSPHRASE` - GPG key passphrase

See `DEPLOYMENT.md` for detailed deployment instructions.

## License

Apache License 2.0 - ensure all new files include proper license headers.
