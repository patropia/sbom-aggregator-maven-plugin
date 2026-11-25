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

import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import static nl.patropia.maven.plugin.GraphAssertions.assertAllReachableFromRoot;
import static nl.patropia.maven.plugin.GraphAssertions.assertPath;
import static nl.patropia.maven.plugin.GraphAssertions.assertReferentialIntegrity;
import static nl.patropia.maven.plugin.GraphAssertions.component;
import static nl.patropia.maven.plugin.GraphAssertions.parents;
import static nl.patropia.maven.plugin.GraphAssertions.refByPurl;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Version-mediation divergence: components that a dependency SBOM lists at a version Maven did not resolve are
 * flagged, but their versions, bom-refs and edges are kept as the sub-SBOM declared them.
 */
class SbomMergerVersionDivergenceTest {

    private static final String ROOT = "pkg:maven/com.acme/root@1.0.0";
    private static final String A = "pkg:maven/com.acme/a@1.0.0";
    private static final String B = "pkg:maven/com.acme/b@1.0.0";
    private static final String C1 = "pkg:maven/com.acme/c@1.0";
    private static final String C2 = "pkg:maven/com.acme/c@2.0";
    private static final String X = "pkg:maven/org.other/x@3.0";
    private static final Instant TS = Instant.parse("2024-01-01T00:00:00Z");

    @TempDir
    Path dir;

    private int counter;

    private static String comp(String bomRef, String purl) {
        String gav = purl.substring("pkg:maven/".length());
        String group = gav.substring(0, gav.indexOf('/'));
        String name = gav.substring(gav.indexOf('/') + 1, gav.indexOf('@'));
        String version = gav.substring(gav.indexOf('@') + 1);
        return "{\"type\":\"library\",\"bom-ref\":\"" + bomRef + "\",\"group\":\"" + group + "\",\"name\":\""
                + name + "\",\"version\":\"" + version + "\",\"purl\":\"" + purl + "\"}";
    }

    private static String dep(String ref, String... dependsOn) {
        StringBuilder sb = new StringBuilder("{\"ref\":\"").append(ref).append('"');
        if (dependsOn.length > 0) {
            sb.append(",\"dependsOn\":[");
            for (int i = 0; i < dependsOn.length; i++) {
                sb.append(i == 0 ? "" : ",").append('"').append(dependsOn[i]).append('"');
            }
            sb.append(']');
        }
        return sb.append('}').toString();
    }

    private Bom bom(String metaComponent, List<String> components, List<String> dependencies) throws Exception {
        String json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,"
                + "\"metadata\":{\"component\":" + metaComponent + "},"
                + "\"components\":[" + String.join(",", components) + "],"
                + "\"dependencies\":[" + String.join(",", dependencies) + "]}";
        Path file = dir.resolve("bom-" + (counter++) + ".json");
        Files.writeString(file, json, StandardCharsets.UTF_8);
        return new JsonParser().parse(file.toFile());
    }

    private static Bom merge(List<Bom> boms, Map<String, String> resolved, String spec) {
        return SbomMerger.merge("com.acme", "root", "1.0.0", spec, boms, null, null, null, TS, true, resolved);
    }

    private static String value(Component component, String name) {
        if (component.getProperties() == null) {
            return null;
        }
        String found = null;
        int count = 0;
        for (Property property : component.getProperties()) {
            if (name.equals(property.getName())) {
                found = property.getValue();
                count++;
            }
        }
        assertEquals(count > 0 ? 1 : 0, count, "property " + name + " must not be duplicated");
        return found;
    }

    /** Own SBOM {@code root -> A}, A's SBOM {@code A -> C@1.0, X}. */
    private List<Bom> chain() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A)), List.of(dep("root", "a"), dep("a")));
        Bom aBom = bom(comp("self", A), List.of(comp("c", C1), comp("x", X)),
                List.of(dep("self", "c", "x"), dep("c"), dep("x")));
        return Arrays.asList(own, aBom);
    }

    /** Own SBOM {@code root -> A, B}; A's SBOM {@code A -> C@1.0}; B's SBOM {@code B -> C@2.0}. */
    private List<Bom> diamond() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A), comp("b", B)),
                List.of(dep("root", "a", "b"), dep("a"), dep("b")));
        Bom aBom = bom(comp("self", A), List.of(comp("lib", C1)), List.of(dep("self", "lib"), dep("lib")));
        Bom bBom = bom(comp("self", B), List.of(comp("lib", C2)), List.of(dep("self", "lib"), dep("lib")));
        return Arrays.asList(own, aBom, bBom);
    }

    @Test
    void divergentVersionIsFlaggedWithMavenResolvedVersion() throws Exception {
        Bom merged = merge(chain(), Map.of("com.acme:c", "2.0", "com.acme:a", "1.0.0"), "1.5");

        Component c = component(merged, refByPurl(merged, C1));
        assertEquals("1.0", c.getVersion(), "the sub-SBOM's version is never rewritten");
        assertEquals("2.0", value(c, SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
        assertEquals("true", value(c, SbomMerger.PROPERTY_VERSION_DIVERGENCE));
        assertPath(merged, ROOT, refByPurl(merged, A), refByPurl(merged, C1));
        assertReferentialIntegrity(merged);
        assertAllReachableFromRoot(merged);
    }

    @Test
    void matchingVersionAndUnknownGaAreLeftAlone() throws Exception {
        Bom merged = merge(chain(), Map.of("com.acme:c", "1.0", "com.acme:a", "1.0.0"), "1.5");

        for (Component component : merged.getComponents()) {
            assertNull(value(component, SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION), component.getPurl());
            assertNull(value(component, SbomMerger.PROPERTY_VERSION_DIVERGENCE), component.getPurl());
        }
        // org.other:x is not in Maven's resolved set (e.g. shaded): untouched
        assertNull(value(component(merged, refByPurl(merged, X)), SbomMerger.PROPERTY_VERSION_DIVERGENCE));
    }

    @Test
    void rootAndPlaceholdersAreNeverFlagged() throws Exception {
        List<SbomMerger.MissingDependency> missing =
                List.of(new SbomMerger.MissingDependency("com.acme", "m", "1.0"));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5", chain(), null, null, missing, TS, true,
                Map.of("com.acme:root", "9.9", "com.acme:m", "2.0"));

        assertNull(value(merged.getMetadata().getComponent(), SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
        Component placeholder = component(merged, refByPurl(merged, "pkg:maven/com.acme/m@1.0"));
        assertNull(value(placeholder, SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
    }

    @Test
    void diamondKeepsBothVersionsAndAllEdgesAndFlagsOnlyTheLoser() throws Exception {
        Bom merged = merge(diamond(), Map.of("com.acme:c", "2.0"), "1.5");

        assertReferentialIntegrity(merged);
        assertAllReachableFromRoot(merged);
        String a = refByPurl(merged, A);
        String b = refByPurl(merged, B);
        String c1 = refByPurl(merged, C1);
        String c2 = refByPurl(merged, C2);
        assertNotEquals(c1, c2, "both versions are kept as distinct components");
        assertEquals(4, merged.getComponents().size(), "A, B, C@1.0 and C@2.0");
        assertEquals(Collections.singleton(a), parents(merged, c1));
        assertEquals(Collections.singleton(b), parents(merged, c2));
        assertPath(merged, ROOT, a, c1);
        assertPath(merged, ROOT, b, c2);

        assertEquals("2.0", value(component(merged, c1), SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
        assertEquals("true", value(component(merged, c1), SbomMerger.PROPERTY_VERSION_DIVERGENCE));
        assertNull(value(component(merged, c2), SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
        assertNull(value(component(merged, c2), SbomMerger.PROPERTY_VERSION_DIVERGENCE));
    }

    @Test
    void sameDivergedComponentInTwoSbomsGetsNoDuplicateProperties() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A), comp("b", B)),
                List.of(dep("root", "a", "b"), dep("a"), dep("b")));
        Bom aBom = bom(comp("self", A), List.of(comp("lib", C1)), List.of(dep("self", "lib")));
        Bom bBom = bom(comp("self", B), List.of(comp("other", C1)), List.of(dep("self", "other")));

        Bom merged = merge(Arrays.asList(own, aBom, bBom), Map.of("com.acme:c", "2.0"), "1.5");

        String c = refByPurl(merged, C1);
        assertEquals(new TreeSet<>(Arrays.asList(refByPurl(merged, A), refByPurl(merged, B))), parents(merged, c));
        // value() asserts each property occurs exactly once
        assertEquals("2.0", value(component(merged, c), SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION));
        assertEquals("true", value(component(merged, c), SbomMerger.PROPERTY_VERSION_DIVERGENCE));
    }

    @Test
    void nullOrEmptyMapProducesTheSameOutputAsTheExistingOverload() throws Exception {
        String legacy = json(SbomMerger.merge("com.acme", "root", "1.0.0", "1.5", diamond(), null, null, null,
                TS, true));
        assertEquals(legacy, json(merge(diamond(), null, "1.5")));
        assertEquals(legacy, json(merge(diamond(), Collections.emptyMap(), "1.5")));
        assertNotEquals(legacy, json(merge(diamond(), Map.of("com.acme:c", "2.0"), "1.5")));
    }

    @Test
    void graphInvariantsHoldForEverySpecVersion() throws Exception {
        for (String spec : Arrays.asList("1.3", "1.4", "1.5", "1.6", "1.7")) {
            Bom merged = merge(diamond(), Map.of("com.acme:c", "2.0"), spec);
            assertReferentialIntegrity(merged);
            assertAllReachableFromRoot(merged);
            assertEquals("2.0", value(component(merged, refByPurl(merged, C1)),
                    SbomMerger.PROPERTY_MAVEN_RESOLVED_VERSION), spec);
        }
    }

    private static String json(Bom bom) throws Exception {
        return BomGeneratorFactory.createJson(Version.VERSION_15, bom).toJsonString();
    }
}
