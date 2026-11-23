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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.cyclonedx.model.Bom;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Compares a baseline CycloneDX SBOM (e.g. the SBOM of the previous release) with the current one and writes a
 * JSON and/or Markdown report of added, removed and changed components and new/resolved vulnerabilities.
 * <p>
 * Bound to {@code verify} by default so it runs after {@code aggregate-sboms} (bound to {@code package}) and can
 * compare the freshly aggregated SBOM. Optionally fails the build when new vulnerabilities appear.
 * </p>
 */
@Mojo(name = "diff-sboms", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class DiffSbomMojo extends AbstractMojo {

    static final String JSON_REPORT = "sbom-diff.json";
    static final String MARKDOWN_REPORT = "sbom-diff.md";
    private static final Set<String> SUPPORTED_FORMATS = new LinkedHashSet<>(Arrays.asList("json", "markdown"));

    /** Baseline SBOM (CycloneDX JSON or XML) to compare against, typically the SBOM of the previous release. */
    @Parameter(property = "sbomAggregator.diff.baseline")
    private File baseline;

    /**
     * Current SBOM (CycloneDX JSON or XML). When not set, the aggregated SBOM of {@code aggregate-sboms} is used:
     * {@code ${project.build.directory}/<outputName>.<outputExtension>}.
     */
    @Parameter(property = "sbomAggregator.diff.current")
    private File current;

    /** Build directory used to locate the aggregated SBOM when {@code current} is not set. */
    @Parameter(defaultValue = "${project.build.directory}", readonly = true)
    private File buildDirectory;

    /**
     * Base name of the aggregated SBOM written by {@code aggregate-sboms}; only used to derive the default for
     * {@code current}.
     */
    @Parameter(property = "sbomAggregator.outputName", defaultValue = "aggregated-bom")
    private String outputName;

    /**
     * Extension ({@code json} or {@code xml}) of the aggregated SBOM written by {@code aggregate-sboms}; only used
     * to derive the default for {@code current}.
     */
    @Parameter(property = "sbomAggregator.outputExtension", defaultValue = "json")
    private String outputExtension;

    /** Report formats to write: {@code json} and/or {@code markdown}. */
    @Parameter(property = "sbomAggregator.diff.reportFormats", defaultValue = "json,markdown")
    private List<String> reportFormats;

    /** Directory where {@code sbom-diff.json} / {@code sbom-diff.md} are written. */
    @Parameter(property = "sbomAggregator.diff.outputDirectory", defaultValue = "${project.build.directory}")
    private File outputDirectory;

    /** Fail the build when the current SBOM contains vulnerabilities that are not in the baseline. */
    @Parameter(property = "sbomAggregator.diff.failOnNewVulnerabilities", defaultValue = "false")
    private boolean failOnNewVulnerabilities;

    /** Skip the diff. */
    @Parameter(property = "sbomAggregator.diff.skip", defaultValue = "false")
    private boolean skip;

    /** Maximum size of each input SBOM file; shared with {@code aggregate-sboms}. */
    @Parameter(property = "sbomAggregator.maxSbomSize", defaultValue = "50MB")
    private String maxSbomSize = "50MB";

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("SBOM diff skipped (sbomAggregator.diff.skip=true)");
            return;
        }
        Set<String> formats = validateFormats(reportFormats);
        long maxBytes = SpecValidation.parseMaxBytes(maxSbomSize);
        if (outputDirectory == null) {
            throw new MojoExecutionException("outputDirectory must be set");
        }

        Bom baselineBom = readSbom("baseline", baseline, maxBytes);
        Bom currentBom = readSbom("current", currentSbom(), maxBytes);
        SbomDiffReport report = SbomDiff.diff(baselineBom, currentBom);

        try {
            Files.createDirectories(outputDirectory.toPath());
            if (formats.contains("json")) {
                File out = new File(outputDirectory, JSON_REPORT);
                Files.write(out.toPath(), toJson(report).getBytes(StandardCharsets.UTF_8));
                getLog().info("SBOM diff JSON report written to " + out.getAbsolutePath());
            }
            if (formats.contains("markdown")) {
                File out = new File(outputDirectory, MARKDOWN_REPORT);
                Files.write(out.toPath(), toMarkdown(report).getBytes(StandardCharsets.UTF_8));
                getLog().info("SBOM diff Markdown report written to " + out.getAbsolutePath());
            }
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to write SBOM diff report: " + e.getMessage(), e);
        }

        getLog().info(String.format(Locale.ROOT,
                "SBOM diff: %d added, %d removed, %d changed, %d unchanged components; %d new, %d resolved vulnerabilities",
                report.getAddedComponents().size(), report.getRemovedComponents().size(),
                report.getChangedComponents().size(), report.getUnchangedCount(),
                report.getNewVulnerabilities().size(), report.getResolvedVulnerabilities().size()));

        if (!report.getNewVulnerabilities().isEmpty()) {
            String ids = report.getNewVulnerabilities().stream()
                    .map(SbomDiffReport.VulnerabilityChange::getId)
                    .distinct()
                    .collect(Collectors.joining(", "));
            if (failOnNewVulnerabilities) {
                throw new MojoFailureException("New vulnerabilities compared to the baseline SBOM: " + ids
                        + " (sbomAggregator.diff.failOnNewVulnerabilities=true)");
            }
            getLog().warn("New vulnerabilities compared to the baseline SBOM: " + ids);
        }
    }

    private static Set<String> validateFormats(List<String> formats) throws MojoExecutionException {
        Set<String> result = new LinkedHashSet<>();
        if (formats == null || formats.isEmpty()) {
            result.addAll(SUPPORTED_FORMATS);
            return result;
        }
        for (String raw : formats) {
            if (raw == null) {
                continue;
            }
            for (String part : raw.split(",")) {
                String f = part.trim().toLowerCase(Locale.ROOT);
                if (f.isEmpty()) {
                    continue;
                }
                if ("md".equals(f)) {
                    f = "markdown";
                }
                if (!SUPPORTED_FORMATS.contains(f)) {
                    throw new MojoExecutionException("Unsupported SBOM diff report format '" + part.trim()
                            + "'. Supported formats: " + String.join(", ", SUPPORTED_FORMATS));
                }
                result.add(f);
            }
        }
        if (result.isEmpty()) {
            throw new MojoExecutionException("reportFormats must contain at least one of: "
                    + String.join(", ", SUPPORTED_FORMATS));
        }
        return result;
    }

    /**
     * Returns the configured {@code current} SBOM, or the aggregated SBOM written by {@code aggregate-sboms}
     * ({@code <buildDirectory>/<outputName>.<outputExtension>}) when it is not set.
     */
    File currentSbom() {
        if (current != null) {
            return current;
        }
        if (buildDirectory == null) {
            return null;
        }
        String name = outputName == null || outputName.trim().isEmpty() ? "aggregated-bom" : outputName.trim();
        String extension = outputExtension == null || outputExtension.trim().isEmpty()
                ? "json" : outputExtension.trim().toLowerCase(Locale.ROOT);
        return new File(buildDirectory, name + "." + extension);
    }

    private Bom readSbom(String role, File file, long maxBytes) throws MojoFailureException {
        if (file == null) {
            throw new MojoFailureException("No " + role + " SBOM configured; set sbomAggregator.diff." + role);
        }
        if (!file.isFile()) {
            throw new MojoFailureException("The " + role + " SBOM does not exist: " + file.getAbsolutePath());
        }
        try {
            return new SbomInputReader(maxBytes).read(file);
        } catch (SbomInputReader.InvalidSbomException e) {
            throw new MojoFailureException("The " + role + " SBOM could not be read: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------- JSON report

    static String toJson(SbomDiffReport report) throws IOException {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("added", report.getAddedComponents().size());
        summary.put("removed", report.getRemovedComponents().size());
        summary.put("changed", report.getChangedComponents().size());
        summary.put("unchanged", report.getUnchangedCount());
        summary.put("newVulnerabilities", report.getNewVulnerabilities().size());
        summary.put("resolvedVulnerabilities", report.getResolvedVulnerabilities().size());
        root.put("summary", summary);
        Map<String, Object> components = new LinkedHashMap<>();
        components.put("added", componentsJson(report.getAddedComponents()));
        components.put("removed", componentsJson(report.getRemovedComponents()));
        components.put("changed", componentsJson(report.getChangedComponents()));
        root.put("components", components);
        Map<String, Object> vulns = new LinkedHashMap<>();
        vulns.put("new", vulnerabilitiesJson(report.getNewVulnerabilities()));
        vulns.put("resolved", vulnerabilitiesJson(report.getResolvedVulnerabilities()));
        root.put("vulnerabilities", vulns);
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        return mapper.writeValueAsString(root).replace("\r\n", "\n") + "\n";
    }

    private static List<Map<String, Object>> componentsJson(List<SbomDiffReport.ComponentChange> changes) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (SbomDiffReport.ComponentChange c : changes) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("key", c.getKey());
            m.put("group", c.getGroup());
            m.put("name", c.getName());
            m.put("change", c.getType().name().toLowerCase(Locale.ROOT));
            m.put("baselineVersion", c.getBaselineVersion());
            m.put("currentVersion", c.getCurrentVersion());
            list.add(m);
        }
        return list;
    }

    private static List<Map<String, Object>> vulnerabilitiesJson(List<SbomDiffReport.VulnerabilityChange> changes) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (SbomDiffReport.VulnerabilityChange v : changes) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", v.getId());
            m.put("source", v.getSource());
            m.put("severity", v.getSeverity());
            m.put("affects", v.getAffects());
            list.add(m);
        }
        return list;
    }

    // ---------------------------------------------------------------- Markdown report

    static String toMarkdown(SbomDiffReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("# SBOM diff\n\n");
        sb.append("| Added | Removed | Changed | Unchanged | New vulnerabilities | Resolved vulnerabilities |\n");
        sb.append("|---:|---:|---:|---:|---:|---:|\n");
        sb.append("| ").append(report.getAddedComponents().size())
                .append(" | ").append(report.getRemovedComponents().size())
                .append(" | ").append(report.getChangedComponents().size())
                .append(" | ").append(report.getUnchangedCount())
                .append(" | ").append(report.getNewVulnerabilities().size())
                .append(" | ").append(report.getResolvedVulnerabilities().size()).append(" |\n");

        appendComponents(sb, "Added components", report.getAddedComponents());
        appendComponents(sb, "Removed components", report.getRemovedComponents());
        appendComponents(sb, "Changed components", report.getChangedComponents());
        appendVulnerabilities(sb, "New vulnerabilities", report.getNewVulnerabilities());
        appendVulnerabilities(sb, "Resolved vulnerabilities", report.getResolvedVulnerabilities());
        return sb.toString();
    }

    private static void appendComponents(StringBuilder sb, String title, List<SbomDiffReport.ComponentChange> list) {
        sb.append("\n## ").append(title).append("\n\n");
        if (list.isEmpty()) {
            sb.append("None.\n");
            return;
        }
        sb.append("| Component | Change | Baseline version | Current version |\n");
        sb.append("|---|---|---|---|\n");
        for (SbomDiffReport.ComponentChange c : list) {
            sb.append("| ").append(escape(c.getDisplayName()))
                    .append(" | ").append(c.getType().name().toLowerCase(Locale.ROOT))
                    .append(" | ").append(escape(c.getBaselineVersion()))
                    .append(" | ").append(escape(c.getCurrentVersion())).append(" |\n");
        }
    }

    private static void appendVulnerabilities(StringBuilder sb, String title,
                                              List<SbomDiffReport.VulnerabilityChange> list) {
        sb.append("\n## ").append(title).append("\n\n");
        if (list.isEmpty()) {
            sb.append("None.\n");
            return;
        }
        sb.append("| Id | Source | Severity | Affects |\n");
        sb.append("|---|---|---|---|\n");
        for (SbomDiffReport.VulnerabilityChange v : list) {
            String affects = v.getAffects().stream().map(DiffSbomMojo::escape).collect(Collectors.joining(", "));
            sb.append("| ").append(escape(v.getId()))
                    .append(" | ").append(escape(v.getSource()))
                    .append(" | ").append(escape(v.getSeverity()))
                    .append(" | ").append(affects).append(" |\n");
        }
    }

    /**
     * Escapes an untrusted SBOM value for a Markdown table cell: Markdown/HTML metacharacters are backslash-escaped
     * or replaced by entities and line breaks become spaces, so a value cannot break the table or inject HTML.
     */
    static String escape(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\r':
                case '\n':
                case '\t':
                    sb.append(' ');
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '&':
                    sb.append("&amp;");
                    break;
                case '|':
                case '`':
                case '*':
                case '_':
                case '[':
                case ']':
                case '\\':
                case '#':
                case '!':
                    sb.append('\\').append(ch);
                    break;
                default:
                    if (Character.isISOControl(ch)) {
                        sb.append(' ');
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- test hooks

    void setBaseline(File baseline) { this.baseline = baseline; }
    void setCurrent(File current) { this.current = current; }
    void setBuildDirectory(File buildDirectory) { this.buildDirectory = buildDirectory; }
    void setOutputName(String outputName) { this.outputName = outputName; }
    void setOutputExtension(String outputExtension) { this.outputExtension = outputExtension; }
    void setReportFormats(List<String> reportFormats) { this.reportFormats = reportFormats; }
    void setOutputDirectory(File outputDirectory) { this.outputDirectory = outputDirectory; }
    void setFailOnNewVulnerabilities(boolean failOnNewVulnerabilities) {
        this.failOnNewVulnerabilities = failOnNewVulnerabilities;
    }
    void setSkip(boolean skip) { this.skip = skip; }
    void setMaxSbomSize(String maxSbomSize) { this.maxSbomSize = maxSbomSize; }
}
