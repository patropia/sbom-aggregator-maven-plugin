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
import java.util.List;

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
        List<String> missingDeps = Collections.singletonList("com.unhappy:missing-lib:3.0.0");

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

    @Test
    void testMergePreservesRootComponentMetadata(@TempDir Path tempDir) {
        MavenProject project = new MavenProject();
        project.setGroupId("com.example");
        project.setArtifactId("my-app");
        project.setVersion("3.2.1");

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(project, Collections.emptyList(), Collections.emptyList());

        assertNotNull(merged.getMetadata());
        assertNotNull(merged.getMetadata().getComponent());
        
        org.cyclonedx.model.Component root = merged.getMetadata().getComponent();
        assertEquals("my-app", root.getName());
        assertEquals("3.2.1", root.getVersion());
        assertEquals("com.example", root.getGroup());
        assertEquals(org.cyclonedx.model.Component.Type.APPLICATION, root.getType());
        assertEquals("pkg:maven/com.example/my-app@3.2.1", root.getPurl());
    }

    @Test
    void testMergeWithMultipleUpstreamBoms(@TempDir Path tempDir) throws Exception {
        MavenProject project = new MavenProject();
        project.setGroupId("nl.patropia");
        project.setArtifactId("aggregator-test");
        project.setVersion("1.0.0");

        // Create two upstream BOMs
        File bom1 = tempDir.resolve("upstream1.json").toFile();
        String json1 = "{\n" +
                "  \"bomFormat\": \"CycloneDX\",\n" +
                "  \"specVersion\": \"1.5\",\n" +
                "  \"version\": 1,\n" +
                "  \"components\": [\n" +
                "    {\n" +
                "      \"type\": \"library\",\n" +
                "      \"name\": \"lib-a\",\n" +
                "      \"version\": \"1.0.0\",\n" +
                "      \"purl\": \"pkg:maven/com.example/lib-a@1.0.0\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        try (FileWriter writer = new FileWriter(bom1)) {
            writer.write(json1);
        }

        File bom2 = tempDir.resolve("upstream2.json").toFile();
        String json2 = "{\n" +
                "  \"bomFormat\": \"CycloneDX\",\n" +
                "  \"specVersion\": \"1.5\",\n" +
                "  \"version\": 1,\n" +
                "  \"components\": [\n" +
                "    {\n" +
                "      \"type\": \"library\",\n" +
                "      \"name\": \"lib-b\",\n" +
                "      \"version\": \"2.0.0\",\n" +
                "      \"purl\": \"pkg:maven/com.example/lib-b@2.0.0\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        try (FileWriter writer = new FileWriter(bom2)) {
            writer.write(json2);
        }

        JsonParser parser = new JsonParser();
        Bom parsedBom1 = parser.parse(bom1);
        Bom parsedBom2 = parser.parse(bom2);

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(project, Arrays.asList(parsedBom1, parsedBom2), Collections.emptyList());

        assertNotNull(merged.getComponents());
        assertEquals(2, merged.getComponents().size());

        boolean hasLibA = merged.getComponents().stream().anyMatch(c -> c.getName().equals("lib-a"));
        boolean hasLibB = merged.getComponents().stream().anyMatch(c -> c.getName().equals("lib-b"));

        assertTrue(hasLibA, "Should include lib-a from first upstream BOM");
        assertTrue(hasLibB, "Should include lib-b from second upstream BOM");
    }

    @Test
    void testMalformedCoordinatesHandledGracefully() {
        MavenProject project = new MavenProject();
        project.setGroupId("nl.patropia");
        project.setArtifactId("test");
        project.setVersion("1.0.0");

        // Test with malformed coordinates (missing parts)
        List<String> malformedDeps = Arrays.asList(
            "incomplete:coord",  // Only 2 parts
            "single",            // Only 1 part
            ""                   // Empty string
        );

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(project, Collections.emptyList(), malformedDeps);

        // Should not crash, but won't create components for malformed coordinates
        assertNotNull(merged);
        assertNotNull(merged.getComponents());
        // Only well-formed coordinates should create components
        assertEquals(0, merged.getComponents().size());
    }

    @Test
    void testDependencyTreeStructure() {
        MavenProject project = new MavenProject();
        project.setGroupId("nl.patropia");
        project.setArtifactId("root-app");
        project.setVersion("1.0.0");

        List<String> missingDeps = Collections.singletonList("com.example:dep:1.0.0");

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(project, Collections.emptyList(), missingDeps);

        assertNotNull(merged.getDependencies());
        assertFalse(merged.getDependencies().isEmpty());

        // Find root dependency
        String rootPurl = "pkg:maven/nl.patropia/root-app@1.0.0";
        org.cyclonedx.model.Dependency rootDep = merged.getDependencies().stream()
            .filter(d -> rootPurl.equals(d.getRef()))
            .findFirst()
            .orElse(null);

        assertNotNull(rootDep, "Root dependency should exist in dependency tree");
        assertNotNull(rootDep.getDependencies(), "Root should have child dependencies");
        assertFalse(rootDep.getDependencies().isEmpty(), "Root should have at least one child");
    }

    // ------------------------------------------------------------------ parseOutputTimestamp

    @Test
    void parseOutputTimestampAcceptsIsoWithOffset() throws Exception {
        assertEquals(java.time.Instant.parse("2024-01-01T08:00:00Z"),
                AggregateSbomMojo.parseOutputTimestamp("2024-01-01T10:00:00+02:00"));
        assertEquals(java.time.Instant.parse("2024-01-01T00:00:00Z"),
                AggregateSbomMojo.parseOutputTimestamp(" 2024-01-01T00:00:00Z "));
    }

    @Test
    void parseOutputTimestampAcceptsEpochSeconds() throws Exception {
        assertEquals(java.time.Instant.ofEpochSecond(1704067200L),
                AggregateSbomMojo.parseOutputTimestamp("1704067200"));
    }

    @Test
    void parseOutputTimestampTreatsEmptyAndPlaceholderAsDisabled() throws Exception {
        assertNull(AggregateSbomMojo.parseOutputTimestamp(null));
        assertNull(AggregateSbomMojo.parseOutputTimestamp(""));
        assertNull(AggregateSbomMojo.parseOutputTimestamp("  "));
        assertNull(AggregateSbomMojo.parseOutputTimestamp("-"));
    }

    @Test
    void parseOutputTimestampRejectsInvalidValues() {
        for (String bad : Arrays.asList("abc", "-123", "2024-13-01T00:00:00Z")) {
            org.apache.maven.plugin.MojoExecutionException error = assertThrows(
                    org.apache.maven.plugin.MojoExecutionException.class,
                    () -> AggregateSbomMojo.parseOutputTimestamp(bad));
            assertTrue(error.getMessage().contains("sbomAggregator.outputTimestamp"), error.getMessage());
            assertTrue(error.getMessage().contains(bad), error.getMessage());
        }
    }
}
