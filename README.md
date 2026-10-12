# \# SBOM Aggregator Maven Plugin

# 

# \[!\[CI](https://github.com/patropia/sbom-aggregator-maven-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/patropia/sbom-aggregator-maven-plugin/actions/workflows/ci.yml)

# \[!\[License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

# 

# A Maven plugin designed for Software Composition Analysis (SCA) in large multi-repository software projects. It aggregates CycloneDX Software Bill of Materials (SBOMs) from dependent projects in-memory, maintains hierarchical traceability, and provides visibility into dependencies that fail to supply an SBOM.

# 

# \---

# 

# \## Features

# 

# \* \*\*In-Memory Merging:\*\* Powered directly by `cyclonedx-core-java`—no external CLI binaries required on build runners.

# \* \*\*Hierarchical Traceability:\*\* Automatically builds a structured dependency tree rooted at your application component.

# \* \*\*Missing SBOM Detection \& Fallbacks:\*\* Identifies dependencies lacking an attached SBOM, logs warnings, and generates placeholder components so your supply-chain visibility has no blind spots.

# \* \*\*Flexible Target Spec Version:\*\* Supports generating output matching CycloneDX spec versions `1.3`, `1.4`, `1.5`, `1.6`, and `1.7`.

# 

# \---

# 

# \## Prerequisites

# 

# \* \*\*Java:\*\* 17 or higher

# \* \*\*Maven:\*\* 3.9.x or higher

# 

# \---

# 

# \## Installation \& Usage

# 

# Add the plugin to your project's `pom.xml` under the desired build lifecycle phase (e.g., `verify`):

# 

# ```xml

# <plugin>

# &#x20;   <groupId>nl.patropia.maven.plugin</groupId>

# &#x20;   <artifactId>sbom-aggregator-maven-plugin</artifactId>

# &#x20;   <version>1.0.0-SNAPSHOT</version>

# &#x20;   <executions>

# &#x20;       <execution>

# &#x20;           <phase>verify</phase>

# &#x20;           <goals>

# &#x20;               <goal>aggregate-sboms</goal>

# &#x20;           </goals>

# &#x20;           <configuration>

# &#x20;               <!-- Path to your project's base SBOM generated in an earlier stage -->

# &#x20;               <projectSbom>${project.build.directory}/bom.json</projectSbom>

# &#x20;               <!-- Target spec version for the merged output -->

# &#x20;               <specVersion>1.5</specVersion>

# &#x20;               <!-- Whether to fail the build if a direct dependency lacks an SBOM -->

# &#x20;               <failOnMissingSbom>false</failOnMissingSbom>

# &#x20;           </configuration>

# &#x20;       </execution>

# &#x20;   </executions>

# </plugin>

# ```

# 

# \---

# 

# \## Configuration Parameters

# 

# | Parameter | Type | Default Value | Description |

# | :--- | :--- | :--- | :--- |

# | `projectSbom` | `File` | `${project.build.directory}/bom.json` | Path to the base project's CycloneDX SBOM. |

# | `outputDirectory` | `File` | `${project.build.directory}` | Directory where the aggregated SBOM will be written. |

# | `sbomClassifier` | `String` | `cyclonedx` | Artifact classifier used when resolving dependent SBOMs. |

# | `sbomExtension` | `String` | `json` | File format/extension (`json` or `xml`). |

# | `specVersion` | `String` | `1.5` | Target CycloneDX specification version (`1.3`, `1.4`, `1.5`, `1.6`, `1.7`). |

# | `failOnMissingSbom` | `boolean` | `false` | Fails the build if any direct dependency fails to provide an attached SBOM. |

# 

# \---

# 

# \## Upstream Project Setup

# 

# To ensure upstream repositories publish their SBOMs correctly so this plugin can resolve them, configure the official `cyclonedx-maven-plugin` to attach the BOM as an artifact:

# 

# ```xml

# <plugin>

# &#x20;   <groupId>org.cyclonedx</groupId>

# &#x20;   <artifactId>cyclonedx-maven-plugin</artifactId>

# &#x20;   <version>2.8.0</version>

# &#x20;   <executions>

# &#x20;       <execution>

# &#x20;           <phase>package</phase>

# &#x20;           <goals>

# &#x20;               <goal>makeAggregateBom</goal>

# &#x20;           </goals>

# &#x20;       </execution>

# &#x20;   </executions>

# &#x20;   <configuration>

# &#x20;       <attach>true</attach>

# &#x20;       <outputFormat>json</outputFormat>

# &#x20;   </configuration>

# </plugin>

# ```

# 

# \---

# 

# \## Building and Testing

# 

# To compile the plugin and run the integration tests locally:

# 

# ```bash

# mvn clean verify -Prun-its

# ```

# 

# To run quick unit tests:

# 

# ```bash

# mvn test

# ```

# 

# \---

# 

# \## License

# 

# Distributed under the \*\*Apache License 2.0\*\*. See `LICENSE` for more information.

