package nl.patropia.maven.plugin;

import org.apache.maven.project.MavenProject;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class AggregateSbomMojoTest {

    @Test
    void testHierarchicalMergeWithMissingSbomFallback(@TempDir Path tempDir) throws Exception {
        // 1. Create a dummy MavenProject representing the root app
        MavenProject project = new MavenProject();
        project.setGroupId("nl.patropia.app");
        project.setArtifactId("root-service");
        project.setVersion("1.0.0");

        // 2. Create Sample SBOM from an upstream dependent project
        File bomFile1 = tempDir.resolve("upstream-bom.json").toFile();
        String json1 = "{\n" +
                "  \"bomFormat\": \"CycloneDX\",\n" +
                "  \"specVersion\": \"1.5\",\n" +
                "  \"version\": 1,\n" +
                "  \"components\": [\n" +
                "    {\n" +
                "      \"type\": \"library\",\n" +
                "      \"name\": \"upstream-lib\",\n" +
                "      \"version\": \"1.2.0\",\n" +
                "      \"purl\": \"pkg:maven/com.upstream/upstream-lib@1.2.0\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        try (FileWriter writer = new FileWriter(bomFile1)) {
            writer.write(json1);
        }

        JsonParser parser = new JsonParser();
        Bom parsedUpstreamBom = parser.parse(bomFile1);

        // 3. Define a dependency missing an SBOM
        java.util.List<String> missingDeps = Collections.singletonList("com.unhappy:missing-lib:3.0.0");

        // 4. Test Mojo's hierarchical merge logic
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(project, Collections.singletonList(parsedUpstreamBom), missingDeps);

        // 5. Assertions for Traceability & Fallbacks
        assertNotNull(merged);
        assertNotNull(merged.getMetadata());
        assertEquals("root-service", merged.getMetadata().getComponent().getName());

        // Should include both the upstream component and the missing-lib placeholder component
        assertNotNull(merged.getComponents());
        assertEquals(2, merged.getComponents().size());

        boolean hasUpstream = merged.getComponents().stream().anyMatch(c -> c.getName().equals("upstream-lib"));
        boolean hasMissingFallback = merged.getComponents().stream().anyMatch(c -> c.getName().equals("missing-lib") && c.getVersion().equals("3.0.0"));

        assertTrue(hasUpstream, "Merged BOM should include upstream component");
        assertTrue(hasMissingFallback, "Merged BOM should create a placeholder component for dependencies lacking an SBOM");

        // Verify root dependency wiring graph
        assertNotNull(merged.getDependencies());
        assertFalse(merged.getDependencies().isEmpty());
    }

    @Test
    void testMalformedSbomThrowsException(@TempDir Path tempDir) throws Exception {
        // 1. Create a malformed/corrupted JSON file
        File malformedFile = tempDir.resolve("corrupted-bom.json").toFile();
        try (FileWriter writer = new FileWriter(malformedFile)) {
            writer.write("{ \"bomFormat\": \"CycloneDX\", invalid json syntax... ");
        }

        // 2. Verify that the parser throws an exception when attempting to parse invalid content
        JsonParser parser = new JsonParser();
        assertThrows(Exception.class, () -> {
            parser.parse(malformedFile);
        }, "Parsing a malformed JSON file should throw an exception");
    }

    @Test
    void testMergeWithEmptyBomsAndMissingDependencies(@TempDir Path tempDir) {
        // 1. Setup root project configuration
        MavenProject project = new MavenProject();
        project.setGroupId("nl.patropia.app");
        project.setArtifactId("fallback-service");
        project.setVersion("2.1.0");

        // 2. Simulate scenario where no attached SBOMs were found, but a dependency lacks an SBOM
        List<String> missingDeps = Arrays.asList(
            "org.legacy:unsupported-lib:1.0.0",
            "org.external:no-sbom-dep:4.5.0"
        );

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        
        // 3. Execute merge with an empty list of parsed upstream BOMs
        Bom merged = mojo.mergeBoms(project, Collections.emptyList(), missingDeps);

        // 4. Assertions for graceful fallback handling
        assertNotNull(merged, "Merged BOM should not be null even when upstream BOMs are empty");
        assertNotNull(merged.getMetadata());
        assertEquals("fallback-service", merged.getMetadata().getComponent().getName());

        // Both missing dependencies should be registered as components via fallback placeholders
        assertNotNull(merged.getComponents());
        assertEquals(2, merged.getComponents().size(), "Should contain fallback components for all missing SBOM dependencies");

        boolean hasUnsupported = merged.getComponents().stream().anyMatch(c -> c.getName().equals("unsupported-lib"));
        boolean hasNoSbomDep = merged.getComponents().stream().anyMatch(c -> c.getName().equals("no-sbom-dep"));

        assertTrue(hasUnsupported, "Should include fallback component for unsupported-lib");
        assertTrue(hasNoSbomDep, "Should include fallback component for no-sbom-dep");

        // Verify root dependency connections are still correctly wired
        assertNotNull(merged.getDependencies());
        assertFalse(merged.getDependencies().isEmpty());
    }
}