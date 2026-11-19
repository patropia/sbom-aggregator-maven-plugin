# SBOM Aggregator Maven Plugin

[![CI](https://github.com/patropia/sbom-aggregator-maven-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/patropia/sbom-aggregator-maven-plugin/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/nl.patropia.maven.plugin/sbom-aggregator-maven-plugin.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22nl.patropia.maven.plugin%22%20AND%20a:%22sbom-aggregator-maven-plugin%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

A Maven plugin designed for Software Composition Analysis (SCA) in large multi-repository software projects. It aggregates CycloneDX Software Bill of Materials (SBOMs) from dependent projects in-memory, maintains hierarchical traceability, and provides visibility into dependencies that fail to supply an SBOM.

---

## Features

* **In-Memory Merging:** Powered directly by `cyclonedx-core-java`—no external CLI binaries required on build runners.
* **Hierarchical Traceability:** Automatically builds a structured dependency tree rooted at your application component.
* **Missing SBOM Detection & Fallbacks:** Identifies dependencies lacking an attached SBOM, logs warnings, and generates placeholder components so your supply-chain visibility has no blind spots.
* **Flexible Target Spec Version:** Supports generating output matching CycloneDX spec versions `1.3`, `1.4`, `1.5`, `1.6`, and `1.7`.

---

## Prerequisites

* **Java:** 17 or higher
* **Maven:** 3.9.x or higher

---

## Installation & Usage

Add the plugin to your project's `pom.xml` under the desired build lifecycle phase (e.g., `verify`):

```xml
<plugin>
    <groupId>nl.patropia.maven.plugin</groupId>
    <artifactId>sbom-aggregator-maven-plugin</artifactId>
    <version>1.0.0</version>
    <executions>
        <execution>
            <phase>verify</phase>
            <goals>
                <goal>aggregate-sboms</goal>
            </goals>
            <configuration>
                <!-- Path to your project's base SBOM generated in an earlier stage -->
                <projectSbom>${project.build.directory}/bom.json</projectSbom>
                <!-- Target spec version for the merged output -->
                <specVersion>1.5</specVersion>
                <!-- Whether to fail the build if a collected dependency (direct, plus transitive when includeTransitive=true) lacks an SBOM -->
                <failOnMissingSbom>false</failOnMissingSbom>
            </configuration>
        </execution>
    </executions>
</plugin>
```

---

## Configuration Parameters

| Parameter | User property | Type | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `projectSbom` | `sbomAggregator.projectSbom` | `File` | `${project.build.directory}/bom.json` | Path to the base project's CycloneDX SBOM. |
| `outputDirectory` | `sbomAggregator.outputDirectory` | `File` | `${project.build.directory}` | Directory where the aggregated SBOM will be written. |
| `dependencyClassifiers` | `sbomAggregator.dependencyClassifiers` | `List<String>` | `["cyclonedx"]` | List of artifact classifiers to try when resolving dependent SBOMs. |
| `dependencyExtensions` | `sbomAggregator.dependencyExtensions` | `List<String>` | `["json", "xml"]` | List of file extensions to try when resolving dependent SBOMs. |
| `includeTransitive` | `sbomAggregator.includeTransitive` | `boolean` | `false` | Whether to include transitive dependencies when collecting SBOMs. |
| `includeScopes` | `sbomAggregator.includeScopes` | `List<String>` | `compile,runtime` | Comma-separated list of scopes to include when resolving transitive dependencies. |
| `excludes` | `sbomAggregator.excludes` | `List<String>` | (empty) | List of dependency coordinates to exclude, pattern `groupId:artifactId` with `*` wildcard. |
| `outputClassifier` | `sbomAggregator.outputClassifier` | `String` | `cyclonedx` | Classifier for the output aggregated SBOM artifact. |
| `outputExtension` | `sbomAggregator.outputExtension` | `String` | `json` | File format/extension for the output aggregated SBOM (`json` or `xml`). |
| `outputName` | `sbomAggregator.outputName` | `String` | `aggregated-bom` | Base filename for the aggregated SBOM output (without extension). |
| `attach` | `sbomAggregator.attach` | `boolean` | `true` | Whether to attach the aggregated SBOM as a project artifact. |
| `skip` | `sbomAggregator.skip` | `boolean` | `false` | Skip execution of the plugin. |
| `specVersion` | `sbomAggregator.specVersion` | `String` | `1.5` | Target CycloneDX specification version (`1.3`, `1.4`, `1.5`, `1.6`, `1.7`). |
| `failOnMissingSbom` | `sbomAggregator.failOnMissingSbom` | `boolean` | `false` | Fails the build if any collected dependency (direct, plus transitive when `includeTransitive=true`) fails to provide an attached SBOM. |

---

## Upstream Project Setup

To ensure upstream repositories publish their SBOMs correctly so this plugin can resolve them, configure the official `cyclonedx-maven-plugin` to attach the BOM as an artifact:

```xml
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <version>2.8.0</version>
    <executions>
        <execution>
            <phase>package</phase>
            <goals>
                <goal>makeAggregateBom</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <attach>true</attach>
        <outputFormat>json</outputFormat>
    </configuration>
</plugin>
```

---

## Quick Start Example

Here's a complete example showing how to use this plugin in a multi-module project:

```xml
<project>
    <!-- ... -->
    <build>
        <plugins>
            <!-- First, generate your project's base SBOM -->
            <plugin>
                <groupId>org.cyclonedx</groupId>
                <artifactId>cyclonedx-maven-plugin</artifactId>
                <version>2.8.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>makeAggregateBom</goal>
                        </goals>
                    </execution>
                </executions>
                <configuration>
                    <outputFormat>json</outputFormat>
                    <outputName>bom</outputName>
                </configuration>
            </plugin>
            
            <!-- Then aggregate with dependencies' SBOMs -->
            <plugin>
                <groupId>nl.patropia.maven.plugin</groupId>
                <artifactId>sbom-aggregator-maven-plugin</artifactId>
                <version>1.0.0</version>
                <executions>
                    <execution>
                        <phase>verify</phase>
                        <goals>
                            <goal>aggregate-sboms</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

After running `mvn verify`, you'll find the aggregated SBOM at `target/aggregated-bom.json`.

### Configuring Dependency Resolution

If your dependencies use different classifier or format conventions for their SBOMs, you can configure multiple options to try:

```xml
<plugin>
    <groupId>nl.patropia.maven.plugin</groupId>
    <artifactId>sbom-aggregator-maven-plugin</artifactId>
    <version>1.0.0</version>
    <executions>
        <execution>
            <phase>verify</phase>
            <goals>
                <goal>aggregate-sboms</goal>
            </goals>
            <configuration>
                <!-- Try multiple classifiers -->
                <dependencyClassifiers>
                    <classifier>cyclonedx</classifier>
                    <classifier>sbom</classifier>
                    <classifier>bom</classifier>
                </dependencyClassifiers>
                <!-- Try multiple formats -->
                <dependencyExtensions>
                    <extension>json</extension>
                    <extension>xml</extension>
                </dependencyExtensions>
            </configuration>
        </execution>
    </executions>
</plugin>
```

The plugin will try each combination of extension and classifier in order for each dependency until it finds an attached SBOM.

### Customizing Output Format

You can control the format and classifier of the generated aggregated SBOM:

```xml
<configuration>
    <outputExtension>xml</outputExtension>
    <outputClassifier>aggregated-sbom</outputClassifier>
    <specVersion>1.6</specVersion>
</configuration>
```

---

## Building and Testing

### Prerequisites

Install Maven if not already available:

```bash
# On Debian/Ubuntu
apt-get install maven

# On macOS
brew install maven

# On Termux (Android)
pkg install maven
```

### Build Commands

To compile the plugin and run the integration tests locally:

```bash
mvn clean verify -Prun-its
```

To run quick unit tests only:

```bash
mvn test
```

To install the plugin locally for testing in other projects:

```bash
mvn clean install
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Roadmap

- [x] Support for transitive dependency SBOM resolution
- [ ] Enhanced vulnerability correlation across aggregated components
- [ ] SBOM diff reporting between versions
- [ ] Support for SPDX format in addition to CycloneDX

---

## License

Distributed under the **Apache License 2.0**. See `LICENSE` for more information.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/patropia/sbom-aggregator-maven-plugin/issues)
- **Discussions**: [GitHub Discussions](https://github.com/patropia/sbom-aggregator-maven-plugin/discussions)
