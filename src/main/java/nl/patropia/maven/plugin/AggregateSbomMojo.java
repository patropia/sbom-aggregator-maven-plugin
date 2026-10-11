package nl.patropia.maven.plugin;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.xml.BomXmlGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.parsers.Parser;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

@Mojo(
    name = "aggregate-sboms",
    defaultPhase = LifecyclePhase.VERIFY,
    requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME
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
     * Classifier used when dependencies publish their attached SBOMs.
     */
    @Parameter(property = "sbomClassifier", defaultValue = "cyclonedx")
    private String sbomClassifier;

    /**
     * File extension/format for the target SBOM ("json" or "xml").
     */
    @Parameter(property = "sbomExtension", defaultValue = "json")
    private String sbomExtension;

    /**
     * Spec version to target (e.g., "1.4", "1.5", "1.6", "1.7").
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

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    private RepositorySystemSession repoSession;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        List<File> sbomFilesToMerge = new ArrayList<>();

        // 1. Collect base project SBOM
        if (projectSbom.exists()) {
            sbomFilesToMerge.add(projectSbom);
            getLog().info("Included base project SBOM: " + projectSbom.getAbsolutePath());
        } else {
            getLog().warn("Base project SBOM not found at: " + projectSbom.getAbsolutePath());
        }

        List<String> missingSboms = new ArrayList<>();

        // 2. Resolve dependency SBOM artifacts
        for (org.apache.maven.model.Dependency dep : project.getDependencies()) {
            String artifactCoords = String.format("%s:%s:%s:%s:%s",
                    dep.getGroupId(), dep.getArtifactId(), sbomExtension, sbomClassifier, dep.getVersion());

            Artifact sbomArtifact = new DefaultArtifact(artifactCoords);
            ArtifactRequest request = new ArtifactRequest();
            request.setArtifact(sbomArtifact);
            request.setRepositories(project.getRemoteProjectRepositories());

            try {
                ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
                File resolvedFile = result.getArtifact().getFile();
                if (resolvedFile != null && resolvedFile.exists()) {
                    sbomFilesToMerge.add(resolvedFile);
                    getLog().info("Resolved attached SBOM for: " + dep.getGroupId() + ":" + dep.getArtifactId());
                }
            } catch (Exception e) {
                String depId = dep.getGroupId() + ":" + dep.getArtifactId() + ":" + dep.getVersion();
                missingSboms.add(depId);
                getLog().warn("MISSING SBOM: Could not resolve attached SBOM for dependency [" + depId + "]");
            }
        }

        // Summary reporting for missing SBOMs
        if (!missingSboms.isEmpty()) {
            getLog().warn("=================================================");
            getLog().warn("Dependencies missing attached SBOMs (" + missingSboms.size() + "):");
            for (String missing : missingSboms) {
                getLog().warn(" - " + missing);
            }
            getLog().warn("=================================================");

            if (failOnMissingSbom) {
                throw new MojoFailureException("Build failed due to missing attached SBOMs for " + missingSboms.size() + " dependencies.");
            }
        }

        if (sbomFilesToMerge.isEmpty()) {
            getLog().warn("No SBOM files available to aggregate.");
            return;
        }

        // 3. Parse and Merge BOMs using the v13 parser API
        List<Bom> boms = new ArrayList<>();
        Parser parser = new Parser();
        for (File file : sbomFilesToMerge) {
            try {
                Bom parsedBom = parser.parse(file);
                if (parsedBom != null) {
                    boms.add(parsedBom);
                }
            } catch (Exception e) {
                getLog().error("Failed to parse SBOM file: " + file.getAbsolutePath(), e);
                throw new MojoExecutionException("Error parsing SBOM: " + file.getName(), e);
            }
        }

        getLog().info("Merging " + boms.size() + " BOMs in-memory...");
        Bom mergedBom = mergeBoms(boms);

        // 4. Serialize and output merged BOM
        File outputFile = new File(outputDirectory, "aggregated-bom." + sbomExtension);
        writeBomToFile(mergedBom, outputFile);
    }

    private Bom mergeBoms(List<Bom> boms) {
        Bom masterBom = new Bom();
        List<org.cyclonedx.model.Component> allComponents = new ArrayList<>();
        List<Dependency> allDependencies = new ArrayList<>();

        for (Bom bom : boms) {
            if (bom.getComponents() != null) {
                allComponents.addAll(bom.getComponents());
            }
            if (bom.getDependencies() != null) {
                allDependencies.addAll(bom.getDependencies());
            }
        }

        if (!allComponents.isEmpty()) {
            masterBom.setComponents(allComponents);
        }
        if (!allDependencies.isEmpty()) {
            masterBom.setDependencies(allDependencies);
        }

        return masterBom;
    }

    private void writeBomToFile(Bom bom, File outputFile) throws MojoExecutionException {
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        Version targetVersion = parseVersion(specVersion);

        try (FileWriter writer = new FileWriter(outputFile)) {
            String bomContent;
            if ("json".equalsIgnoreCase(sbomExtension)) {
                BomJsonGenerator generator = BomGeneratorFactory.createJson(targetVersion, bom);
                bomContent = generator.toJsonString();
            } else {
                BomXmlGenerator generator = BomGeneratorFactory.createXml(targetVersion, bom);
                bomContent = generator.toXmlString();
            }

            writer.write(bomContent);
            getLog().info("Successfully generated merged SBOM at: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to write merged SBOM to output file", e);
        }
    }

    private Version parseVersion(String versionStr) {
        switch (versionStr) {
            case "1.7": return Version.VERSION_17;
            case "1.6": return Version.VERSION_16;
            case "1.4": return Version.VERSION_14;
            case "1.3": return Version.VERSION_13;
            case "1.5":
            default: return Version.VERSION_15;
        }
    }
}