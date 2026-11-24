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

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
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
import org.cyclonedx.parsers.Parser;
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
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
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

    /** Classifier of the attached SPDX document. */
    static final String SPDX_CLASSIFIER = "spdx";

    /** File type of the attached SPDX document (JSON). */
    static final String SPDX_FILE_TYPE = "json";

    /** Suffix of the SPDX file name; the format is fixed to SPDX 2.3 JSON. */
    static final String SPDX_FILE_SUFFIX = "spdx.json";

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * Path to the current project's base SBOM created in an earlier build phase.
     */
    @Parameter(property = "sbomAggregator.projectSbom", defaultValue = "${project.build.directory}/bom.json", required = true)
    private File projectSbom;

    /**
     * Output directory for the aggregated SBOM.
     */
    @Parameter(property = "sbomAggregator.outputDirectory", defaultValue = "${project.build.directory}", required = true)
    private File outputDirectory;

    /**
     * Classifiers to try when resolving dependencies' attached SBOMs.
     * The plugin will attempt each classifier in order until a match is found.
     * Default: ["cyclonedx"]
     */
    @Parameter(property = "sbomAggregator.dependencyClassifiers")
    private List<String> dependencyClassifiers;

    /**
     * File extensions to try when resolving dependencies' attached SBOMs.
     * The plugin will attempt each extension in order until a match is found.
     * Default: ["json", "xml"]
     */
    @Parameter(property = "sbomAggregator.dependencyExtensions")
    private List<String> dependencyExtensions;

    /**
     * Include transitive dependencies when resolving attached SBOMs. Defaults to false (only direct deps).
     */
    @Parameter(property = "sbomAggregator.includeTransitive", defaultValue = "false")
    boolean includeTransitive;

    /**
     * Merge the {@code vulnerabilities} sections of the input SBOMs into the aggregated BOM (spec 1.4+).
     * Duplicates (same id and source) are merged and {@code affects} references are rewritten to the
     * final component bom-refs. Defaults to true.
     */
    @Parameter(property = "sbomAggregator.includeVulnerabilities", defaultValue = "true")
    boolean includeVulnerabilities = true;

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
    @Parameter(property = "sbomAggregator.outputExtension", defaultValue = "json")
    private String outputExtension;

    /**
     * Spec version to target (e.g., "1.3", "1.4", "1.5", "1.6", "1.7").
     */
    @Parameter(property = "sbomAggregator.specVersion", defaultValue = "1.5")
    private String specVersion;

    /**
     * Optional output timestamp to make generated SBOMs deterministic. Accepts ISO-8601 or epoch
     * seconds. When unset or blank the plugin will use the current time and a random serial.
     */
    @Parameter(property = "sbomAggregator.outputTimestamp", defaultValue = "${project.build.outputTimestamp}")
    private String outputTimestamp;

    /** Maximum size for input SBOM files. Accepts bytes or with KB/MB/GB suffix (case-insensitive); 0 = unlimited. */
    @Parameter(property = "sbomAggregator.maxSbomSize", defaultValue = "50MB")
    private String maxSbomSize = "50MB";

    /**
     * Validate the aggregated SBOM against the official CycloneDX JSON/XML schema of the configured
     * {@code specVersion} before it is written. A document that does not conform fails the build and no
     * output file is produced. Set to {@code false} to skip validation.
     */
    @Parameter(property = "sbomAggregator.validateOutput", defaultValue = "true")
    private boolean validateOutput = true;

    /** When true, a dependency SBOM that fails to parse will fail the build; when false, the dependency will be treated as missing and a placeholder will be emitted. */
    @Parameter(property = "sbomAggregator.failOnInvalidSbom", defaultValue = "true")
    private boolean failOnInvalidSbom = true;

    // parsed value in bytes; computed early during validateConfiguration()
    private long maxSbomBytes = 0L;

    /**
     * Whether to fail the build if a collected dependency lacks an attached SBOM.
     * <p>
     * Applies to every dependency the plugin inspects: direct dependencies by default, and also
     * transitive dependencies when {@code includeTransitive} is enabled.
     * </p>
     */
    @Parameter(property = "sbomAggregator.failOnMissingSbom", defaultValue = "false")
    private boolean failOnMissingSbom;

    /**
     * CycloneDX SBOMs produced by scanners (e.g. Syft or Trivy output for a container image, file system or a
     * single jar) to merge into the aggregated SBOM.
     * <p>
     * Scan components are matched to Maven components by canonical purl (e.g. {@code ?type=jar} is ignored), and
     * components the scan does not connect are linked under the scan's {@code metadata.component} with the
     * property {@code sbomAggregator:inferredDependency=true}. A scan never decides the {@code dependsOn} of a
     * component that a Maven SBOM describes, even when the scan's own top component has a {@code pkg:maven} purl.
     * A configured file that is missing or not a valid CycloneDX document always fails the build.
     * </p>
     */
    @Parameter(property = "sbomAggregator.scanSboms")
    private List<File> scanSboms;

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
     * Also write the aggregated BOM as an SPDX 2.3 JSON document named
     * {@code <outputName>.spdx.json} in the output directory and, when {@code attach} is enabled, attach it
     * with classifier {@code spdx} and type {@code json}. Default: false
     * <p>
     * The document is generated from the aggregated CycloneDX BOM. SPDX 2.3 has no representation for
     * CycloneDX vulnerabilities, services or compositions, so those sections are not part of the SPDX
     * output. A fixed {@code outputTimestamp} makes the SPDX document reproducible byte for byte.
     * </p>
     */
    @Parameter(property = "sbomAggregator.generateSpdx", defaultValue = "false")
    private boolean generateSpdx;

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
        LinkedHashMap<File, DepCoord> fileToDep = new LinkedHashMap<>();

        // 1. Collect base project SBOM
        if (projectSbom.exists()) {
            sbomFilesToMerge.add(projectSbom);
            fileToDep.put(projectSbom, null);
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
                            fileToDep.put(resolvedFile, dep);
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

        // 3. Parse BOMs using a content-based reader with a size guard
        List<Bom> boms = new ArrayList<>();
        List<String> owners = new ArrayList<>();
        SbomInputReader reader = new SbomInputReader(maxSbomBytes);

        for (File file : sbomFilesToMerge) {
            try {
                Bom parsedBom = reader.read(file);
                if (parsedBom != null) {
                    boms.add(parsedBom);
                    owners.add(ownerPurl(fileToDep.get(file)));
                }
            } catch (SbomInputReader.InvalidSbomException e) {
                DepCoord owner = fileToDep.get(file);
                // Always fail for the project's own SBOM; dependency SBOMs only fail when failOnInvalidSbom is set.
                if (owner == null || failOnInvalidSbom) {
                    throw new MojoExecutionException(e.getMessage(), e);
                }
                getLog().warn(e.getMessage());
                missingSboms.add(new SbomMerger.MissingDependency(owner.groupId, owner.artifactId, owner.version));
            }
        }

        // 3b. Parse explicitly configured scan SBOMs; they were configured on purpose, so problems always fail
        warnDuplicateScanInputs(sbomFilesToMerge);
        List<Bom> scans = readScanSboms(reader);

        if (boms.isEmpty() && scans.isEmpty() && missingSboms.isEmpty()) {
            getLog().warn("No SBOM files available to aggregate - creating minimal SBOM");
        }

        // Summary reporting for missing SBOMs (including dependencies downgraded from invalid to missing)
        if (!missingSboms.isEmpty()) {
            getLog().warn("Missing SBOMs for " + missingSboms.size() + " dependencies");
            getLog().debug("Dependencies without SBOMs: " + missingSboms);

            if (failOnMissingSbom) {
                throw new MojoFailureException("Build failed due to missing attached SBOMs for "
                        + missingSboms.size() + " dependencies.");
            }
        }

        getLog().debug("Merging " + boms.size() + " BOMs and " + scans.size() + " scan SBOMs in-memory");
        Bom mergedBom = SbomMerger.merge(
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion(),
                specVersion,
                boms,
                owners,
                scans,
                missingSboms,
                parseOutputTimestamp(outputTimestamp),
                includeVulnerabilities);

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

        // 5. Optional SPDX 2.3 output for consumers that work with SPDX instead of CycloneDX
        if (generateSpdx) {
            writeSpdxOutput(mergedBom);
        }
    }

    /**
     * Writes the given BOM as an SPDX 2.3 JSON document to {@code <outputDirectory>/<outputName>.spdx.json}
     * and, when {@code attach} is enabled, attaches it to the project with classifier {@code spdx} and type
     * {@code json}.
     *
     * @param bom the aggregated BOM to convert
     * @throws MojoExecutionException when the document cannot be written or attached
     */
    void writeSpdxOutput(Bom bom) throws MojoExecutionException {
        File spdxFile = new File(outputDirectory, outputName + "." + SPDX_FILE_SUFFIX);
        String content = SpdxConverter.toJson(bom, parseOutputTimestamp(outputTimestamp));
        try {
            File parent = spdxFile.getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }
            Files.write(spdxFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            getLog().error("Failed to write SPDX SBOM: " + e.getMessage());
            throw new MojoExecutionException("Failed to write SPDX SBOM to output file: " + e.getMessage(), e);
        }
        getLog().info("SPDX 2.3 SBOM written to: " + spdxFile.getName());

        if (!attach) {
            return;
        }
        if (projectHelper == null) {
            throw new MojoExecutionException("Cannot attach SPDX SBOM because projectHelper is not available");
        }
        try {
            projectHelper.attachArtifact(project, SPDX_FILE_TYPE, SPDX_CLASSIFIER, spdxFile);
            getLog().info("SPDX 2.3 SBOM attached to project with classifier='" + SPDX_CLASSIFIER
                    + "' and type='" + SPDX_FILE_TYPE + "'.");
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to attach SPDX SBOM to project", e);
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
        maxSbomBytes = SpecValidation.parseMaxBytes(maxSbomSize);

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

        // The SPDX document is attached as classifier 'spdx' / type 'json'; a CycloneDX artifact with the
        // same coordinates would be silently replaced, so reject that combination up front.
        if (generateSpdx && attach && outputClassifier != null
                && SPDX_CLASSIFIER.equals(outputClassifier) && SPDX_FILE_TYPE.equals(outputExtension())) {
            throw new MojoExecutionException("outputClassifier '" + SPDX_CLASSIFIER + "' with outputExtension '"
                    + SPDX_FILE_TYPE + "' clashes with the SPDX artifact written by generateSpdx=true; "
                    + "choose a different outputClassifier or disable generateSpdx");
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
     * Parses the configured output timestamp following Maven's own {@code project.build.outputTimestamp} rules.
     *
     * @param value the raw configuration value; may be {@code null}
     * @return the parsed instant, or {@code null} when reproducible output is disabled (value unset, blank or a
     *         single character such as the Maven placeholder {@code -})
     * @throws MojoExecutionException when the value is neither ISO-8601 nor epoch seconds
     */
    static Instant parseOutputTimestamp(String value) throws MojoExecutionException {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 1) {
            // Maven treats an empty value and the placeholder "-" as "reproducible output disabled".
            return null;
        }
        if (trimmed.chars().allMatch(Character::isDigit)) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(trimmed));
            } catch (NumberFormatException e) {
                throw new MojoExecutionException("Invalid sbomAggregator.outputTimestamp '" + value
                        + "': expected ISO-8601 (e.g. 2024-01-01T00:00:00Z) or epoch seconds", e);
            }
        }
        try {
            return OffsetDateTime.parse(trimmed).toInstant();
        } catch (DateTimeParseException e) {
            throw new MojoExecutionException("Invalid sbomAggregator.outputTimestamp '" + value
                    + "': expected ISO-8601 (e.g. 2024-01-01T00:00:00Z) or epoch seconds", e);
        }
    }

    /**
     * Returns the Maven purl of the dependency an SBOM file was attached to, or {@code null} for the project's
     * own SBOM. The merger uses it to anchor the components of a dependency SBOM without
     * {@code metadata.component} under that dependency instead of under the project root.
     */
    static String ownerPurl(DepCoord owner) {
        if (owner == null || owner.groupId == null || owner.artifactId == null || owner.version == null
                || owner.groupId.isEmpty() || owner.artifactId.isEmpty() || owner.version.isEmpty()) {
            return null;
        }
        return Purls.maven(owner.groupId, owner.artifactId, owner.version, null, null);
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
                specVersion,
                parsedBoms == null ? Collections.emptyList() : parsedBoms,
                missing,
                null,
                includeVulnerabilities);
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

            if (validateOutput) {
                validateBomContent(content.getBytes(StandardCharsets.UTF_8), outputExtension(),
                        targetVersion, specVersion, getLog());
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

    /**
     * Validates serialised SBOM bytes against the official CycloneDX schema for the given version.
     *
     * @param content       the serialised SBOM document
     * @param extension     output extension, {@code json} or {@code xml}
     * @param schemaVersion CycloneDX schema version to validate against
     * @param specVersion   the configured spec version, used only in the error message
     * @throws MojoExecutionException when the document does not conform to the schema
     */
    static void validateBomContent(byte[] content, String extension, Version schemaVersion, String specVersion)
            throws MojoExecutionException {
        validateBomContent(content, extension, schemaVersion, specVersion, null);
    }

    /**
     * Same as {@link #validateBomContent(byte[], String, Version, String)} but logs every schema problem at debug
     * level before failing, so a broken build can be diagnosed without re-running the plugin.
     *
     * @param content       the serialised SBOM document
     * @param extension     output extension, {@code json} or {@code xml}
     * @param schemaVersion CycloneDX schema version to validate against
     * @param specVersion   the configured spec version, used only in the error message
     * @param log           logger used for the debug output; may be {@code null}
     * @throws MojoExecutionException when the document does not conform to the schema
     */
    static void validateBomContent(byte[] content, String extension, Version schemaVersion, String specVersion,
                                   Log log)
            throws MojoExecutionException {
        Parser parser = "xml".equals(extension) ? new XmlParser() : new JsonParser();
        List<org.cyclonedx.exception.ParseException> problems;
        try {
            problems = parser.validate(content, schemaVersion);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to validate the generated SBOM: " + e.getMessage(), e);
        }
        if (problems != null && !problems.isEmpty()) {
            if (log != null) {
                log.debug("CycloneDX " + specVersion + " schema reported " + problems.size()
                        + " problem(s) for the generated SBOM:");
                for (int i = 0; i < problems.size(); i++) {
                    log.debug("  [" + (i + 1) + "] " + problems.get(i).getMessage());
                }
            }
            throw new MojoExecutionException("Generated SBOM does not conform to the CycloneDX " + specVersion
                    + " " + extension.toUpperCase(Locale.ROOT) + " schema: " + problems.get(0).getMessage());
        }
    }

    /**
     * Reads the configured {@code scanSboms}. A missing, unreadable or invalid scan file fails the build.
     */
    List<Bom> readScanSboms(SbomInputReader reader) throws MojoExecutionException {
        List<Bom> scans = new ArrayList<>();
        if (scanSboms == null) {
            return scans;
        }
        for (File file : scanSboms) {
            if (file == null) {
                continue;
            }
            if (!file.isFile()) {
                throw new MojoExecutionException("Configured scan SBOM not found: " + file.getAbsolutePath());
            }
            try {
                scans.add(reader.read(file));
                getLog().debug("Read scan SBOM " + file.getAbsolutePath());
            } catch (SbomInputReader.InvalidSbomException e) {
                throw new MojoExecutionException(e.getMessage(), e);
            }
        }
        return scans;
    }

    /**
     * Warns when a configured scan SBOM is also merged as a regular (project or dependency) SBOM. Such a file is
     * merged twice and its scan copy adds nothing.
     */
    void warnDuplicateScanInputs(List<File> sbomFilesToMerge) {
        if (scanSboms == null || sbomFilesToMerge == null || sbomFilesToMerge.isEmpty()) {
            return;
        }
        java.util.Set<String> merged = new java.util.HashSet<>();
        for (File f : sbomFilesToMerge) {
            merged.add(canonicalPath(f));
        }
        for (File scan : scanSboms) {
            if (scan != null && merged.contains(canonicalPath(scan))) {
                getLog().warn("Scan SBOM " + scan.getAbsolutePath()
                        + " is also merged as a project/dependency SBOM; it will be merged twice");
            }
        }
    }

    private static String canonicalPath(File file) {
        try {
            return file.getCanonicalPath();
        } catch (java.io.IOException e) {
            return file.getAbsolutePath();
        }
    }

    // Package-private setters for unit tests.

    void setScanSboms(List<File> scanSboms) {
        this.scanSboms = scanSboms;
    }

    void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    void setOutputTimestamp(String outputTimestamp) { this.outputTimestamp = outputTimestamp; }

    void setMaxSbomSize(String maxSbomSize) { this.maxSbomSize = maxSbomSize; }

    void setValidateOutput(boolean validateOutput) { this.validateOutput = validateOutput; }

    void setFailOnInvalidSbom(boolean failOnInvalidSbom) { this.failOnInvalidSbom = failOnInvalidSbom; }

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
    void setGenerateSpdx(boolean generateSpdx) { this.generateSpdx = generateSpdx; }

    void setProjectHelper(MavenProjectHelper projectHelper) { this.projectHelper = projectHelper; }

    // Package-private setters for new fields (used by unit tests)
    void setIncludeTransitive(boolean includeTransitive) { this.includeTransitive = includeTransitive; }
    void setIncludeScopes(List<String> includeScopes) { this.includeScopes = includeScopes; }
    void setExcludes(List<String> excludes) { this.excludes = excludes; }
}
