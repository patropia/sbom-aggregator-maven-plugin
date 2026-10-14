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
import org.cyclonedx.model.Metadata;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
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
     * Classifier for the output aggregated SBOM artifact.
     * Default: "cyclonedx"
     */
    @Parameter(property = "outputClassifier", defaultValue = "cyclonedx")
    private String outputClassifier;

    /**
     * File extension/format for the output aggregated SBOM ("json" or "xml").
     * Default: "json"
     */
    @Parameter(property = "outputExtension", defaultValue = "json")
    private String outputExtension;

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

        List<String> missingSboms = new ArrayList<>();

        // 2. Resolve dependency SBOM artifacts
        for (org.apache.maven.model.Dependency dep : project.getDependencies()) {
            String depId = dep.getGroupId() + ":" + dep.getArtifactId() + ":" + dep.getVersion();
            boolean resolved = false;

            // Try each combination of extension and classifier
            for (String extension : dependencyExtensions) {
                for (String classifier : dependencyClassifiers) {
                    String artifactCoords = String.format("%s:%s:%s:%s:%s",
                            dep.getGroupId(), dep.getArtifactId(), extension, classifier, dep.getVersion());

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
                    } catch (Exception e) {
                        getLog().debug("Could not resolve SBOM with " + extension + ":" + classifier + " for: " + depId);
                    }
                }
                if (resolved) break; // Stop trying other extensions once we find one
            }

            if (!resolved) {
                missingSboms.add(depId);
                getLog().warn("MISSING SBOM: Could not resolve attached SBOM for dependency [" + depId + "]");
            }
        }

        // Summary reporting for missing SBOMs
        if (!missingSboms.isEmpty()) {
            getLog().warn("Missing SBOMs for " + missingSboms.size() + " dependencies");
            getLog().debug("Dependencies without SBOMs: " + missingSboms);

            if (failOnMissingSbom) {
                throw new MojoFailureException("Build failed due to missing attached SBOMs for " + missingSboms.size() + " dependencies.");
            }
        }

        if (sbomFilesToMerge.isEmpty()) {
            getLog().warn("No SBOM files available to aggregate - creating minimal SBOM");
            
            // Create a minimal BOM even if no files to merge
            Bom minimalBom = mergeBoms(project, Collections.emptyList(), missingSboms);
            File outputFile = new File(outputDirectory, "aggregated-bom." + outputExtension);
            writeBomToFile(minimalBom, outputFile);
            return;
        }

        // 3. Parse BOMs using JsonParser or XmlParser
        List<Bom> boms = new ArrayList<>();
        JsonParser jsonParser = new JsonParser();
        XmlParser xmlParser = new XmlParser();

        for (File file : sbomFilesToMerge) {
            try {
                Bom parsedBom;
                if (file.getName().toLowerCase().endsWith(".xml")) {
                    parsedBom = xmlParser.parse(file);
                } else {
                    parsedBom = jsonParser.parse(file);
                }

                if (parsedBom != null) {
                    boms.add(parsedBom);
                }
            } catch (Exception e) {
                getLog().error("Failed to parse SBOM file: " + file.getAbsolutePath(), e);
                throw new MojoExecutionException("Error parsing SBOM: " + file.getName(), e);
            }
        }

        getLog().debug("Merging " + boms.size() + " BOMs in-memory");
        Bom mergedBom = mergeBoms(project, boms, missingSboms);

        // 4. Serialize and output merged BOM
        File outputFile = new File(outputDirectory, "aggregated-bom." + outputExtension);
        writeBomToFile(mergedBom, outputFile);
        getLog().info("Aggregated SBOM written to: " + outputFile.getName());
    }

    Bom mergeBoms(MavenProject mavenProject, List<Bom> parsedBoms, List<String> missingDepsCoords) {
        Bom masterBom = new Bom();

        // 1. Establish Root Project Metadata & Component
        Metadata metadata = new Metadata();
        org.cyclonedx.model.Component rootComponent = new org.cyclonedx.model.Component();
        rootComponent.setType(org.cyclonedx.model.Component.Type.APPLICATION);
        rootComponent.setGroup(mavenProject.getGroupId());
        rootComponent.setName(mavenProject.getArtifactId());
        rootComponent.setVersion(mavenProject.getVersion());
        rootComponent.setPurl(String.format("pkg:maven/%s/%s@%s", mavenProject.getGroupId(), mavenProject.getArtifactId(), mavenProject.getVersion()));
        metadata.setComponent(rootComponent);
        masterBom.setMetadata(metadata);

        List<org.cyclonedx.model.Component> allComponents = new ArrayList<>();
        List<Dependency> allDependencies = new ArrayList<>();
        List<Dependency> childDependencies = new ArrayList<>();

        // Add components and dependency trees from successfully parsed SBOMs
        for (Bom bom : parsedBoms) {
            if (bom.getComponents() != null) {
                allComponents.addAll(bom.getComponents());
            }
            if (bom.getDependencies() != null) {
                allDependencies.addAll(bom.getDependencies());
            }
        }

        // 2. Handle dependencies that DO NOT provide an SBOM (create fallback components)
        for (String missingCoord : missingDepsCoords) {
            String[] parts = missingCoord.split(":");
            if (parts.length >= 3) {
                String g = parts[0];
                String a = parts[1];
                String v = parts[2];

                org.cyclonedx.model.Component missingComp = new org.cyclonedx.model.Component();
                missingComp.setType(org.cyclonedx.model.Component.Type.LIBRARY);
                missingComp.setGroup(g);
                missingComp.setName(a);
                missingComp.setVersion(v);
                missingComp.setPurl(String.format("pkg:maven/%s/%s@%s", g, a, v));
                
                allComponents.add(missingComp);
            }
        }

        // 3. Construct explicit dependency tree wiring for the root component
        Dependency rootDependency = new Dependency(rootComponent.getPurl());
        for (org.cyclonedx.model.Component c : allComponents) {
            if (c.getPurl() != null) {
                childDependencies.add(new Dependency(c.getPurl()));
            }
        }
        rootDependency.setDependencies(childDependencies);
        allDependencies.add(rootDependency);

        masterBom.setComponents(allComponents);
        masterBom.setDependencies(allDependencies);

        return masterBom;
    }

    private void writeBomToFile(Bom bom, File outputFile) throws MojoExecutionException {
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        Version targetVersion = parseVersion(specVersion);

        try (FileWriter writer = new FileWriter(outputFile)) {
            String bomContent;
            if ("json".equalsIgnoreCase(outputExtension)) {
                BomJsonGenerator generator = BomGeneratorFactory.createJson(targetVersion, bom);
                bomContent = generator.toJsonString();
            } else {
                BomXmlGenerator generator = BomGeneratorFactory.createXml(targetVersion, bom);
                bomContent = generator.toXmlString();
            }

            writer.write(bomContent);
            writer.flush();
            getLog().debug("Generated SBOM: " + outputFile.length() + " bytes");
        } catch (Exception e) {
            getLog().error("Failed to write SBOM: " + e.getMessage());
            throw new MojoExecutionException("Failed to write merged SBOM to output file: " + e.getMessage(), e);
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
