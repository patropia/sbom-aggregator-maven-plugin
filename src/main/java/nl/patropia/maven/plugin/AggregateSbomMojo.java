/*
 * Copyright 2026 Patrick Schulenberg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.patropia.maven.plugin;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.transfer.ArtifactNotFoundException;

import java.util.LinkedHashMap;
import java.util.regex.Pattern;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Aggregates the project's own CycloneDX SBOM with the SBOMs attached to its dependencies into a
 * single BOM written to the build output directory.
 */
@Mojo(
    name = "aggregate-sboms",
    defaultPhase = LifecyclePhase.VERIFY,
    requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
    threadSafe = true
)
public class AggregateSbomMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    /**
     * Path to the current project's base SBOM created in an earlier build phase.
     */
    @Parameter(property = "projectSbom", defaultValue = "${project.build.directory}/bom.json", required = true)
    private File projectSbom;

    /**
     * Output directory for the aggregated SBOM.
     */
    @Parameter(property = "outputDirectory", defaultValue = "${project.build.directory}", required = true)
    private File outputDirectory;

    /**
     * Classifiers to try when resolving dependencies' attached SBOMs.
     * The plugin will attempt each classifier in order until a match is found.
     * Default: ["cyclonedx"]
     */
    @Parameter(property = "dependencyClassifiers")
    private List<String> dependencyClassifiers;

    /**
     * File extensions to try when resolving dependencies' attached SBOMs.
     * The plugin will attempt each extension in order until a match is found.
     * Default: ["json", "xml"]
     */
    @Parameter(property = "dependencyExtensions")
    private List<String> dependencyExtensions;

    /**
     * Include transitive dependencies when resolving attached SBOMs. Defaults to false (only direct deps).
     */
    @Parameter(property = "sbomAggregator.includeTransitive", defaultValue = "false")
    boolean includeTransitive;

    /**
     * Scopes to include when collecting dependencies. Null or empty -> ["compile","runtime"].
     */
    @Parameter(property = "sbomAggregator.includeScopes")
    List<String> includeScopes;

    /**
     * Exclude patterns in the form groupId:artifactId where '*' may be used as a wildcard. Only group:artifact part is matched.
     */
    @Parameter(property = "sbomAggregator.excludes")
    List<String> excludes;

    /**
     * Classifier for the output aggregated SBOM artifact.
     * Default: "cyclonedx"
     */
    @Parameter(property = "sbomAggregator.outputClassifier", defaultValue = "cyclonedx")
    private String outputClassifier;

    /**
     * File extension/format for the output aggregated SBOM ("json" or "xml", case-insensitive).
     * Default: "json"
     */
    @Parameter(property = "outputExtension", defaultValue = "json")
    private String outputExtension;

    /**
     * Spec version to target (e.g., "1.3", "1.4", "1.5", "1.6", "1.7").
     */
    @Parameter(property = "specVersion", defaultValue = "1.5")
    private String specVersion;

    /**
     * Whether to fail the build if a direct dependency lacks an attached SBOM.
     */
    @Parameter(property = "failOnMissingSbom", defaultValue = "false")
    private boolean failOnMissingSbom;

    @Component
    private RepositorySystem repoSystem;

    @Component
    private MavenProjectHelper projectHelper;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    /**
     * Whether to attach the aggregated SBOM to the project using outputClassifier/outputExtension.
     * Default: true
     */
    @Parameter(property = "sbomAggregator.attach", defaultValue = "true")
    private boolean attach;

    /**
     * Skip execution
     */
    @Parameter(property = "sbomAggregator.skip", defaultValue = "false")
    private boolean skip;

    /**
     * Base name for the output file (without extension). Default: "aggregated-bom"
     */
    @Parameter(property = "sbomAggregator.outputName", defaultValue = "aggregated-bom")
    private String outputName;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping SBOM aggregation (skip=true)");
            return;
        }

        validateConfiguration();

        // Initialize default values if not provided
        if (dependencyClassifiers == null || dependencyClassifiers.isEmpty()) {
            dependencyClassifiers = new ArrayList<>();
            dependencyClassifiers.add("cyclonedx");
        }

        if (dependencyExtensions == null || dependencyExtensions.isEmpty()) {
            dependencyExtensions = new ArrayList<>();
            dependencyExtensions.add("json");
            dependencyExtensions.add("xml");
        }

        getLog().info("Aggregating SBOMs for " + project.getArtifactId() + ":" + project.getVersion());
        getLog().debug("Base SBOM: " + projectSbom.getAbsolutePath());
        getLog().debug("Output directory: " + outputDirectory.getAbsolutePath());
        getLog().debug("Dependency classifiers: " + dependencyClassifiers);
        getLog().debug("Dependency extensions: " + dependencyExtensions);
        getLog().debug("Output format: " + outputExtension + " (classifier: " + outputClassifier + ")");
        getLog().debug("Spec version: " + specVersion);

        List<File> sbomFilesToMerge = new ArrayList<>();

        // 1. Collect base project SBOM
        if (projectSbom.exists()) {
            sbomFilesToMerge.add(projectSbom);
            getLog().debug("Found base project SBOM");
        } else {
            getLog().warn("Base project SBOM not found at: " + projectSbom.getAbsolutePath());
        }

        List<SbomMerger.MissingDependency> missingSboms = new ArrayList<>();

        // 2. Resolve dependency SBOM artifacts using collected dependency coordinates
        for (DepCoord dep : collectDependencyCoords()) {
            String depId = dep.groupId + ":" + dep.artifactId + ":" + dep.version;
            boolean resolved = false;

            // Try each combination of extension and classifier
            for (String extension : dependencyExtensions) {
                for (String classifier : dependencyClassifiers) {
                    String artifactCoords = String.format("%s:%s:%s:%s:%s",
                            dep.groupId, dep.artifactId, extension, classifier, dep.version);

                    Artifact sbomArtifact = new DefaultArtifact(artifactCoords);
                    ArtifactRequest request = new ArtifactRequest();
                    request.setArtifact(sbomArtifact);
                    request.setRepositories(project.getRemoteProjectRepositories());

                    try {
                        ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
                        File resolvedFile = result.getArtifact().getFile();
                        if (resolvedFile != null && resolvedFile.exists()) {
                            sbomFilesToMerge.add(resolvedFile);
                            getLog().debug("Resolved SBOM for " + depId + " (" + extension + ":" + classifier + ")");
                            resolved = true;
                            break; // Stop trying other classifiers once we find one
                        }
                    } catch (ArtifactResolutionException e) {
                        Throwable cause = e.getCause();
                        if (cause instanceof ArtifactNotFoundException) {
                            getLog().debug("SBOM not found for " + depId + " with " + extension + ":" + classifier + " - " + e.getMessage());
                        } else {
                            getLog().warn("SBOM resolution failed for " + depId + " with " + extension + ":" + classifier
                                    + " - " + e.getMessage() + " (dependency will be reported as missing an SBOM)");
                        }
                    }
                }
                if (resolved) {
                    break; // Stop trying other extensions once we find one
                }
            }

            if (!resolved) {
                missingSboms.add(new SbomMerger.MissingDependency(
                        dep.groupId, dep.artifactId, dep.version));
                getLog().warn("MISSING SBOM: Could not resolve attached SBOM for dependency [" + depId + "]");
            }
        }

        // Summary reporting for missing SBOMs
        if (!missingSboms.isEmpty()) {
            getLog().warn("Missing SBOMs for " + missingSboms.size() + " dependencies");
            getLog().debug("Dependencies without SBOMs: " + missingSboms);

            if (failOnMissingSbom) {
                throw new MojoFailureException("Build failed due to missing attached SBOMs for "
                        + missingSboms.size() + " dependencies.");
            }
        }

        // 3. Parse BOMs using JsonParser or XmlParser
        List<Bom> boms = new ArrayList<>();

        for (File file : sbomFilesToMerge) {
            try {
                Bom parsedBom;
                if (file.getName().toLowerCase(Locale.ROOT).endsWith(".xml")) {
                    parsedBom = new XmlParser().parse(file);
                } else {
                    parsedBom = new JsonParser().parse(file);
                }

                if (parsedBom != null) {
                    boms.add(parsedBom);
                }
            } catch (Exception e) {
                getLog().error("Failed to parse SBOM file: " + file.getAbsolutePath(), e);
                throw new MojoExecutionException("Error parsing SBOM: " + file.getName(), e);
            }
        }

        if (boms.isEmpty() && missingSboms.isEmpty()) {
            getLog().warn("No SBOM files available to aggregate - creating minimal SBOM");
        }

        getLog().debug("Merging " + boms.size() + " BOMs in-memory");
        Bom mergedBom = SbomMerger.merge(
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion(),
                boms,
                missingSboms);

        // 4. Serialize and output merged BOM
        File outputFile = new File(outputDirectory, outputName + "." + outputExtension());
        writeBomToFile(mergedBom, outputFile);
        getLog().info("Aggregated SBOM written to: " + outputFile.getName());

        if (attach) {
            // warn if an artifact with same classifier/type is already attached
            boolean clash = false;
            for (org.apache.maven.artifact.Artifact a : project.getAttachedArtifacts()) {
                String aClassifier = a.getClassifier();
                String aType = a.getType();
                if (Objects.equals(aClassifier, outputClassifier) && Objects.equals(aType, outputExtension())) {
                    clash = true;
                    break;
                }
            }
            if (clash) {
                getLog().warn("Attaching aggregated SBOM will replace an existing attached artifact with classifier '" + outputClassifier + "' and type '" + outputExtension() + "'.");
            }
            if (projectHelper == null) {
                throw new MojoExecutionException("Cannot attach aggregated SBOM because projectHelper is not available");
            }
            try {
                projectHelper.attachArtifact(project, outputExtension(), outputClassifier, outputFile);
                getLog().info("Aggregated SBOM attached to project with classifier='" + outputClassifier + "' and type='" + outputExtension() + "'.");
            } catch (Exception e) {
                throw new MojoExecutionException("Failed to attach aggregated SBOM to project", e);
            }
        }
    }

    /**
     * Collect dependency coordinates from the project according to includeTransitive, includeScopes and excludes.
     * Returns a list preserving first-seen order and deduped by group:artifact:version.
     */
    List<DepCoord> collectDependencyCoords() {
        List<DepCoord> coords = new ArrayList<>();

        // Prepare scopes default
        List<String> scopesToUse = includeScopes == null || includeScopes.isEmpty()
                ? List.of("compile", "runtime")
                : includeScopes;

        // Build exclude patterns
        List<Pattern> excludePatterns = new ArrayList<>();
        if (excludes != null) {
            for (String ex : excludes) {
                if (ex == null || ex.trim().isEmpty()) continue;
                String trimmed = ex.trim();
                // Escape dots and other regex characters except '*' which we translate to '.*'
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < trimmed.length(); i++) {
                    char c = trimmed.charAt(i);
                    if (c == '*') {
                        sb.append(".*");
                    } else {
                        sb.append(Pattern.quote(String.valueOf(c)));
                    }
                }
                excludePatterns.add(Pattern.compile(sb.toString()));
            }
        }

        // Use a LinkedHashMap to dedupe while preserving order: key -> DepCoord
        LinkedHashMap<String, DepCoord> map = new LinkedHashMap<>();

        if (includeTransitive) {
            // Use the project's resolved artifacts
            for (org.apache.maven.artifact.Artifact a : project.getArtifacts()) {
                addCoord(map, a.getGroupId(), a.getArtifactId(), a.getVersion(), a.getScope(), scopesToUse, excludePatterns);
            }
        } else {
            for (org.apache.maven.model.Dependency d : project.getDependencies()) {
                addCoord(map, d.getGroupId(), d.getArtifactId(), d.getVersion(), d.getScope(), scopesToUse, excludePatterns);
            }
        }

        coords.addAll(map.values());
        return coords;
    }

    /**
     * Applies the scope and exclude filters to a single dependency coordinate and, when it passes both,
     * adds it to {@code map} under its group:artifact:version key. First occurrence wins, so the result
     * keeps the order in which dependencies were seen and no SBOM artifact is requested twice.
     */
    private static void addCoord(LinkedHashMap<String, DepCoord> map, String groupId, String artifactId,
                                 String version, String scope, List<String> scopesToUse,
                                 List<Pattern> excludePatterns) {
        String effectiveScope = scope == null ? "compile" : scope;
        if (!scopesToUse.contains(effectiveScope)) {
            return;
        }
        String ga = groupId + ":" + artifactId;
        for (Pattern p : excludePatterns) {
            if (p.matcher(ga).matches()) {
                return;
            }
        }
        map.putIfAbsent(groupId + ":" + artifactId + ":" + version,
                new DepCoord(groupId, artifactId, version, effectiveScope));
    }

    static class DepCoord {
        final String groupId;
        final String artifactId;
        final String version;
        final String scope;

        DepCoord(String groupId, String artifactId, String version, String scope) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.version = version;
            this.scope = scope;
        }
    }

    /**
     * Validates and normalises the plugin configuration. Must run before any resolution work so an
     * invalid configuration fails fast with a clear message.
     */
    void validateConfiguration() throws MojoExecutionException {
        if (specVersion == null) {
            throw new MojoExecutionException("specVersion is required; supported values: "
                    + SpecValidation.SUPPORTED_SPEC_VERSIONS);
        }
        specVersion = specVersion.trim();
        outputExtension = outputExtension();
        if (outputExtension == null || outputExtension.isEmpty()) {
            throw new MojoExecutionException("outputExtension must be set to 'json' or 'xml'");
        }
        SpecValidation.validateSpecVersion(specVersion);
        SpecValidation.validateOutputExtension(outputExtension);

        // validate outputName to avoid writing outside the output directory
        if (outputName == null || outputName.trim().isEmpty()) {
            throw new MojoExecutionException("outputName must not be blank");
        }
        String on = outputName.trim();
        if (on.contains("/") || on.contains("\\") || on.contains("..")) {
            throw new MojoExecutionException("outputName must not contain path separators or '..' to avoid writing outside the output directory");
        }
        outputName = on;

        // An aggregated SBOM that is attached without a classifier would replace the project's main
        // artifact, so a blank classifier is only allowed when attaching is switched off.
        if (outputClassifier == null || outputClassifier.trim().isEmpty()) {
            if (attach) {
                throw new MojoExecutionException("outputClassifier must not be blank when attach=true; "
                        + "an empty classifier would replace the project's main artifact. "
                        + "Set outputClassifier or use -DsbomAggregator.attach=false");
            }
        } else {
            outputClassifier = outputClassifier.trim();
        }
    }

    /**
     * @return the normalised (trimmed, lower-case) output extension, never {@code null} unless it
     *         was not configured at all.
     */
    String outputExtension() {
        if (outputExtension == null) {
            return null;
        }
        return outputExtension.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Merges the given BOMs. Retained as a thin wrapper around {@link SbomMerger#merge} for
     * callers that still hold Maven coordinates as {@code groupId:artifactId:version} strings.
     */
    Bom mergeBoms(MavenProject mavenProject, List<Bom> parsedBoms, List<String> missingDepsCoords) {
        List<SbomMerger.MissingDependency> missing = new ArrayList<>();
        if (missingDepsCoords != null) {
            for (String coordinates : missingDepsCoords) {
                SbomMerger.MissingDependency missingDependency = SbomMerger.MissingDependency.parse(coordinates);
                if (missingDependency != null) {
                    missing.add(missingDependency);
                }
            }
        }
        return SbomMerger.merge(
                mavenProject.getGroupId(),
                mavenProject.getArtifactId(),
                mavenProject.getVersion(),
                parsedBoms == null ? Collections.emptyList() : parsedBoms,
                missing);
    }

    /**
     * Serialises the given BOM in the configured format and spec version, writing it as UTF-8.
     */
    void writeBomToFile(Bom bom, File outputFile) throws MojoExecutionException {
        Version targetVersion = SpecValidation.toCycloneDxVersion(specVersion);

        try {
            String content;
            if ("json".equals(outputExtension())) {
                BomJsonGenerator generator = BomGeneratorFactory.createJson(targetVersion, bom);
                content = generator.toJsonString();
            } else {
                BomXmlGenerator generator = BomGeneratorFactory.createXml(targetVersion, bom);
                content = generator.toXmlString();
            }

            File parent = outputFile.getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }
            try (Writer writer = Files.newBufferedWriter(outputFile.toPath(), StandardCharsets.UTF_8)) {
                writer.write(content);
            }
        } catch (IOException | org.cyclonedx.exception.GeneratorException e) {
            getLog().error("Failed to write SBOM: " + e.getMessage());
            throw new MojoExecutionException("Failed to write merged SBOM to output file: " + e.getMessage(), e);
        }
        getLog().debug("Generated SBOM: " + outputFile.length() + " bytes");
    }

    // Package-private setters for unit tests.

    void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    void setOutputExtension(String outputExtension) {
        this.outputExtension = outputExtension;
    }

    void setOutputClassifier(String outputClassifier) {
        this.outputClassifier = outputClassifier;
    }

    void setOutputDirectory(File outputDirectory) {
        this.outputDirectory = outputDirectory;
    }

    void setProjectSbom(File projectSbom) {
        this.projectSbom = projectSbom;
    }

    // Package-private setters for new fields (used by unit tests)
    void setAttach(boolean attach) { this.attach = attach; }
    void setSkip(boolean skip) { this.skip = skip; }
    void setOutputName(String outputName) { this.outputName = outputName; }

    void setProjectHelper(MavenProjectHelper projectHelper) { this.projectHelper = projectHelper; }

    // Package-private setters for new fields (used by unit tests)
    void setIncludeTransitive(boolean includeTransitive) { this.includeTransitive = includeTransitive; }
    void setIncludeScopes(List<String> includeScopes) { this.includeScopes = includeScopes; }
    void setExcludes(List<String> excludes) { this.excludes = excludes; }
}
