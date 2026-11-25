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

    @Test
    void ownerPurlRequiresCompleteCoordinates() {
        assertEquals("pkg:maven/com.acme/lib@1.0.0",
                AggregateSbomMojo.ownerPurl(new AggregateSbomMojo.DepCoord("com.acme", "lib", "1.0.0", "compile")));
        // incomplete coordinates cannot be expressed as a purl, so the merger has to ignore the owner
        assertNull(AggregateSbomMojo.ownerPurl(null));
        assertNull(AggregateSbomMojo.ownerPurl(new AggregateSbomMojo.DepCoord(null, "lib", "1.0.0", null)));
        assertNull(AggregateSbomMojo.ownerPurl(new AggregateSbomMojo.DepCoord("com.acme", "", "1.0.0", null)));
        assertNull(AggregateSbomMojo.ownerPurl(new AggregateSbomMojo.DepCoord("com.acme", "lib", null, null)));
        assertNull(AggregateSbomMojo.ownerPurl(new AggregateSbomMojo.DepCoord("com.acme", "lib", " ", null)));
    }

    @Test
    void missingScanSbomFailsTheBuild(@TempDir Path tempDir) {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setScanSboms(Collections.singletonList(tempDir.resolve("does-not-exist.json").toFile()));
        org.apache.maven.plugin.MojoExecutionException error = assertThrows(
                org.apache.maven.plugin.MojoExecutionException.class,
                () -> mojo.readScanSboms(new SbomInputReader(0L)));
        assertTrue(error.getMessage().contains("does-not-exist.json"));
    }

    @Test
    void invalidScanSbomFailsTheBuild(@TempDir Path tempDir) throws Exception {
        File invalid = tempDir.resolve("scan.json").toFile();
        try (FileWriter writer = new FileWriter(invalid)) {
            writer.write("{ \"bomFormat\": \"CycloneDX\", invalid json syntax... ");
        }
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setFailOnInvalidSbom(false); // scans were configured explicitly, so this does not apply
        mojo.setScanSboms(Collections.singletonList(invalid));
        assertThrows(org.apache.maven.plugin.MojoExecutionException.class,
                () -> mojo.readScanSboms(new SbomInputReader(0L)));
    }

    @Test
    void validScanSbomsAreRead(@TempDir Path tempDir) throws Exception {
        File scan = tempDir.resolve("scan.json").toFile();
        try (FileWriter writer = new FileWriter(scan)) {
            writer.write("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,"
                    + "\"components\":[{\"type\":\"library\",\"name\":\"bash\",\"version\":\"5.1\","
                    + "\"purl\":\"pkg:rpm/redhat/bash@5.1?arch=x86_64\"}]}");
        }
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        assertTrue(mojo.readScanSboms(new SbomInputReader(0L)).isEmpty(), "no scans configured");
        mojo.setScanSboms(Arrays.asList(scan, null));
        List<Bom> scans = mojo.readScanSboms(new SbomInputReader(0L));
        assertEquals(1, scans.size());
        assertEquals("bash", scans.get(0).getComponents().get(0).getName());
    }

    @Test
    void nullScanSbomsListReturnsEmpty(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setScanSboms(null);
        assertTrue(mojo.readScanSboms(new SbomInputReader(0L)).isEmpty());
        // duplicate check must tolerate null lists/entries without failing
        mojo.warnDuplicateScanInputs(Arrays.asList(tempDir.resolve("a.json").toFile()));
        mojo.setScanSboms(Arrays.asList(tempDir.resolve("a.json").toFile(), null));
        mojo.warnDuplicateScanInputs(Arrays.asList(tempDir.resolve("a.json").toFile()));
    }

    @Test
    void collectDependencyCoordsMarksDirectDependenciesFromTheTrail() throws Exception {
        MavenProject project = new MavenProject();
        project.setGroupId("com.acme");
        project.setArtifactId("root");
        project.setVersion("1.0.0");
        org.apache.maven.artifact.Artifact direct = artifact("com.acme", "a", "1.0.0",
                Arrays.asList("com.acme:root:jar:1.0.0", "com.acme:a:jar:1.0.0"));
        org.apache.maven.artifact.Artifact transitive = artifact("com.acme", "b", "1.0.0",
                Arrays.asList("com.acme:root:jar:1.0.0", "com.acme:a:jar:1.0.0", "com.acme:b:jar:1.0.0"));
        org.apache.maven.artifact.Artifact noTrailDeclared = artifact("com.acme", "c", "1.0.0", null);
        org.apache.maven.artifact.Artifact noTrailUndeclared = artifact("com.acme", "e", "1.0.0", null);
        project.setArtifacts(new java.util.LinkedHashSet<>(
                Arrays.asList(direct, transitive, noTrailDeclared, noTrailUndeclared)));
        org.apache.maven.model.Dependency declaredC = new org.apache.maven.model.Dependency();
        declaredC.setGroupId("com.acme");
        declaredC.setArtifactId("c");
        declaredC.setVersion("1.0.0");
        project.setDependencies(Collections.singletonList(declaredC));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        java.lang.reflect.Field field = AggregateSbomMojo.class.getDeclaredField("project");
        field.setAccessible(true);
        field.set(mojo, project);

        mojo.setIncludeTransitive(true);
        java.util.Map<String, AggregateSbomMojo.DepCoord> byArtifact = new java.util.HashMap<>();
        for (AggregateSbomMojo.DepCoord coord : mojo.collectDependencyCoords()) {
            byArtifact.put(coord.artifactId, coord);
        }
        assertEquals(4, byArtifact.size());
        assertTrue(byArtifact.get("a").direct, "trail of length 2 is a direct dependency");
        assertFalse(byArtifact.get("b").direct, "trail of length 3 is a transitive dependency");
        assertEquals(3, byArtifact.get("b").trail.size());
        assertTrue(byArtifact.get("c").direct, "without a trail a declared dependency is direct");
        assertFalse(byArtifact.get("e").direct, "without a trail an undeclared dependency is transitive");

        mojo.setIncludeTransitive(false);
        List<AggregateSbomMojo.DepCoord> declaredOnly = mojo.collectDependencyCoords();
        assertEquals(1, declaredOnly.size());
        assertTrue(declaredOnly.stream().allMatch(c -> c.direct), "includeTransitive=false: everything is direct");
    }

    @Test
    void collectResolvedVersionsUsesBaseVersionAndIgnoresSbomFilters() throws Exception {
        MavenProject project = new MavenProject();
        project.setGroupId("com.acme");
        project.setArtifactId("root");
        project.setVersion("1.0.0");
        org.apache.maven.artifact.Artifact snapshot = artifact("com.acme", "snap", "1.0-SNAPSHOT", null);
        snapshot.setVersion("1.0-20240101.123456-1");
        org.apache.maven.artifact.Artifact testScoped = new org.apache.maven.artifact.DefaultArtifact(
                "com.acme", "junit-like", "5.0", "test", "jar", null,
                new org.apache.maven.artifact.handler.DefaultArtifactHandler("jar"));
        org.apache.maven.artifact.Artifact excluded = artifact("org.excluded", "lib", "2.0",
                Arrays.asList("com.acme:root:jar:1.0.0", "com.acme:snap:jar:1.0-SNAPSHOT", "org.excluded:lib:jar:2.0"));
        project.setArtifacts(new java.util.LinkedHashSet<>(Arrays.asList(snapshot, testScoped, excluded)));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        java.lang.reflect.Field field = AggregateSbomMojo.class.getDeclaredField("project");
        field.setAccessible(true);
        field.set(mojo, project);
        mojo.setIncludeScopes(Collections.singletonList("compile"));
        mojo.setExcludes(Collections.singletonList("org.excluded:*"));

        for (boolean transitive : new boolean[] {true, false}) {
            mojo.setIncludeTransitive(transitive);
            java.util.Map<String, String> resolved = mojo.collectResolvedVersions();
            assertEquals("1.0-SNAPSHOT", resolved.get("com.acme:snap"), "timestamped SNAPSHOT uses the base version");
            assertEquals("5.0", resolved.get("com.acme:junit-like"), "scope filters do not apply");
            assertEquals("2.0", resolved.get("org.excluded:lib"), "excludes do not apply");
            assertEquals("1.0.0", resolved.get("com.acme:root"), "the project itself is included");
            assertEquals(4, resolved.size());
        }
    }

    private static org.apache.maven.artifact.Artifact artifact(String g, String a, String v, List<String> trail) {
        org.apache.maven.artifact.DefaultArtifact artifact = new org.apache.maven.artifact.DefaultArtifact(
                g, a, v, "compile", "jar", null, new org.apache.maven.artifact.handler.DefaultArtifactHandler("jar"));
        artifact.setDependencyTrail(trail);
        return artifact;
    }

    @Test
    void warnVersionDivergenceNamesGroupFromPurlWhenGroupIsBlank() {
        org.cyclonedx.model.Component component = new org.cyclonedx.model.Component();
        component.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        component.setName("x");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/com.acme/x@1.0");
        org.cyclonedx.model.Property property = new org.cyclonedx.model.Property();
        property.setName(SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION);
        property.setValue("2.0");
        component.setProperties(new java.util.ArrayList<>(Collections.singletonList(property)));
        Bom bom = new Bom();
        bom.setComponents(new java.util.ArrayList<>(Collections.singletonList(component)));

        List<String> warnings = new java.util.ArrayList<>();
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setLog(new org.apache.maven.plugin.logging.SystemStreamLog() {
            @Override
            public void warn(CharSequence content) {
                warnings.add(content.toString());
            }
        });

        mojo.warnVersionDivergence(bom);

        assertEquals(1, warnings.size(), "exactly one divergence warning expected");
        assertTrue(warnings.get(0).contains("com.acme:x: 1.0 -> 2.0"), warnings.get(0));
        assertFalse(warnings.get(0).contains("null:"), warnings.get(0));
    }

    @Test
    void warnVersionDivergenceIsSilentWithoutDivergence() {
        List<String> warnings = new java.util.ArrayList<>();
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setLog(new org.apache.maven.plugin.logging.SystemStreamLog() {
            @Override
            public void warn(CharSequence content) {
                warnings.add(content.toString());
            }
        });
        mojo.warnVersionDivergence(new Bom());
        mojo.warnVersionDivergence(null);
        assertTrue(warnings.isEmpty(), warnings.toString());
    }
}
