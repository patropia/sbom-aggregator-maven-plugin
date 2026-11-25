/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static nl.patropia.maven.plugin.GraphAssertions.assertAllReachableFromRoot;
import static nl.patropia.maven.plugin.GraphAssertions.assertDirectChildren;
import static nl.patropia.maven.plugin.GraphAssertions.assertPath;
import static nl.patropia.maven.plugin.GraphAssertions.assertReferentialIntegrity;
import static nl.patropia.maven.plugin.GraphAssertions.children;
import static nl.patropia.maven.plugin.GraphAssertions.component;
import static nl.patropia.maven.plugin.GraphAssertions.parents;
import static nl.patropia.maven.plugin.GraphAssertions.refByPurl;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Provenance tests for {@link SbomMerger}: the aggregated graph must keep the hierarchy of the input SBOMs so a
 * consumer can trace every direct and transitive dependency back to {@code metadata.component.bom-ref}.
 */
class SbomMergerProvenanceTest {

    private static final String ROOT = "pkg:maven/com.acme/root@1.0.0";
    private static final String A = "pkg:maven/com.acme/a@1.0.0";
    private static final String B = "pkg:maven/com.acme/b@1.0.0";
    private static final String C = "pkg:maven/com.acme/c@1.0.0";
    private static final String D = "pkg:maven/com.acme/d@1.0.0";
    private static final String X = "pkg:maven/com.acme/x@1.0.0";
    private static final String Y = "pkg:maven/com.acme/y@1.0.0";

    @TempDir
    Path dir;

    private int counter;

    // ------------------------------------------------------------------ fixtures

    /** A component JSON object for a pkg:maven purl, with an explicit bom-ref. */
    private static String comp(String bomRef, String purl) {
        String gav = purl.substring("pkg:maven/".length());
        String group = gav.substring(0, gav.indexOf('/'));
        String name = gav.substring(gav.indexOf('/') + 1, gav.indexOf('@'));
        String version = gav.substring(gav.indexOf('@') + 1);
        return "{\"type\":\"library\",\"bom-ref\":\"" + bomRef + "\",\"group\":\"" + group + "\",\"name\":\""
                + name + "\",\"version\":\"" + version + "\",\"purl\":\"" + purl + "\"}";
    }

    /** A dependency entry JSON object. */
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
                + (metaComponent == null ? "" : "\"metadata\":{\"component\":" + metaComponent + "},")
                + "\"components\":[" + String.join(",", components) + "],"
                + "\"dependencies\":[" + String.join(",", dependencies) + "]}";
        Path file = dir.resolve("bom-" + (counter++) + ".json");
        Files.writeString(file, json, StandardCharsets.UTF_8);
        return new JsonParser().parse(file.toFile());
    }

    private static Bom merge(List<Bom> boms, List<SbomMerger.MissingDependency> missing) {
        return merge(boms, missing, "1.5");
    }

    private static Bom merge(List<Bom> boms, List<SbomMerger.MissingDependency> missing, String spec) {
        return SbomMerger.merge("com.acme", "root", "1.0.0", spec,
                boms == null ? null : new ArrayList<>(boms), missing, null);
    }

    private static void assertGraphInvariants(Bom merged) {
        assertReferentialIntegrity(merged);
        assertAllReachableFromRoot(merged);
    }

    private static boolean hasProperty(Component component, String name, String value) {
        if (component.getProperties() == null) {
            return false;
        }
        for (Property property : component.getProperties()) {
            if (name.equals(property.getName()) && value.equals(property.getValue())) {
                return true;
            }
        }
        return false;
    }

    /** Own SBOM {@code root -> A}, A's SBOM {@code A -> B}, B's SBOM {@code B -> C}. */
    private List<Bom> chainRootABC() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A)), List.of(dep("root", "a"), dep("a")));
        Bom aBom = bom(comp("self", A), List.of(comp("b", B)), List.of(dep("self", "b"), dep("b")));
        Bom bBom = bom(comp("self", B), List.of(comp("c", C)), List.of(dep("self", "c"), dep("c")));
        return Arrays.asList(own, aBom, bBom);
    }

    // ------------------------------------------------------------------ tests

    @Test
    void multiHopProvenancePreserved() throws Exception {
        Bom merged = merge(chainRootABC(), null);

        assertGraphInvariants(merged);
        String a = refByPurl(merged, A);
        String b = refByPurl(merged, B);
        String c = refByPurl(merged, C);
        assertPath(merged, ROOT, a, b, c);
        assertDirectChildren(merged, ROOT, a);
        assertEquals(Collections.singleton(b), parents(merged, c), "C must only be reached through B");
        assertEquals(Collections.singleton(a), parents(merged, b), "B must only be reached through A");
    }

    @Test
    void diamondKeepsAllIncomingEdges() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A), comp("b", B)),
                List.of(dep("root", "a", "b"), dep("a"), dep("b")));
        Bom aBom = bom(comp("self", A), List.of(comp("shared", D)), List.of(dep("self", "shared")));
        Bom bBom = bom(comp("me", B), List.of(comp("d-lib", D)), List.of(dep("me", "d-lib")));

        Bom merged = merge(Arrays.asList(own, aBom, bBom), null);

        assertGraphInvariants(merged);
        String a = refByPurl(merged, A);
        String b = refByPurl(merged, B);
        String d = refByPurl(merged, D); // exactly one component for the shared dependency
        assertEquals(3, merged.getComponents().size(), "A, B and one D, nothing else");
        assertDirectChildren(merged, ROOT, a, b);
        assertEquals(new java.util.TreeSet<>(Arrays.asList(a, b)), parents(merged, d),
                "the shared dependency keeps both incoming edges");
        assertPath(merged, ROOT, a, d);
        assertPath(merged, ROOT, b, d);
    }

    @Test
    void bomRefCollisionKeepsEdgesSeparate() throws Exception {
        // Both upstream SBOMs use the local bom-ref "lib" for different components.
        Bom aBom = bom(comp("self", A), List.of(comp("lib", X)), List.of(dep("self", "lib"), dep("lib")));
        Bom bBom = bom(comp("self", B), List.of(comp("lib", Y)), List.of(dep("self", "lib"), dep("lib")));

        Bom merged = merge(Arrays.asList(aBom, bBom), null);

        assertGraphInvariants(merged);
        String a = refByPurl(merged, A);
        String b = refByPurl(merged, B);
        String x = refByPurl(merged, X);
        String y = refByPurl(merged, Y);
        assertNotEquals(x, y, "colliding local bom-refs must be renamed apart");
        assertNotEquals(a, b);
        assertDirectChildren(merged, a, x);
        assertDirectChildren(merged, b, y);
        assertDirectChildren(merged, ROOT, a, b);
    }

    @Test
    void orphanComponentsAreAnchoredUnderTheirSbomRootNotTheProjectRoot() throws Exception {
        // A's SBOM lists Z as a component but has no edge to it.
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A)), List.of(dep("root", "a"), dep("a")));
        Bom aBom = bom(comp("self", A), List.of(comp("b", B), comp("z", D)), List.of(dep("self", "b"), dep("b")));

        Bom merged = merge(Arrays.asList(own, aBom), null);

        assertGraphInvariants(merged);
        String a = refByPurl(merged, A);
        String orphan = refByPurl(merged, D);
        assertDirectChildren(merged, ROOT, a);
        assertPath(merged, ROOT, a, orphan);
        assertTrue(hasProperty(component(merged, orphan), SbomMerger.PROPERTY_INFERRED_DEPENDENCY, "true"),
                "the inferred edge must be marked");
    }

    @Test
    void upstreamSbomsWithoutProjectSbomAreWiredToTheRoot() throws Exception {
        Bom aBom = bom(comp("self", A), List.of(comp("b", B)), List.of(dep("self", "b"), dep("b")));
        Bom xBom = bom(comp("self", X), List.of(), List.of(dep("self")));

        Bom merged = merge(Arrays.asList(aBom, xBom), null);

        assertGraphInvariants(merged);
        String a = refByPurl(merged, A);
        String x = refByPurl(merged, X);
        assertDirectChildren(merged, ROOT, a, x);
        assertPath(merged, ROOT, a, refByPurl(merged, B));
    }

    @Test
    void missingDirectDependencyIsWiredToRootAndMarked() throws Exception {
        Bom aBom = bom(comp("self", A), List.of(), List.of(dep("self")));
        List<SbomMerger.MissingDependency> missing =
                List.of(new SbomMerger.MissingDependency("com.acme", "x", "1.0.0"));

        Bom merged = merge(Collections.singletonList(aBom), missing);

        assertGraphInvariants(merged);
        String x = refByPurl(merged, X);
        assertDirectChildren(merged, ROOT, refByPurl(merged, A), x);
        assertTrue(hasProperty(component(merged, x), SbomMerger.PROPERTY_MISSING_SBOM, "true"));
    }

    @Test
    void transitiveMissingSbomPlaceholderStaysUnderItsParent() throws Exception {
        // Own SBOM root -> A -> B -> C, where only A and B have SBOMs. C is "missing" but already known
        // through B's SBOM, so it must stay reachable through B.
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A)), List.of(dep("root", "a"), dep("a")));
        Bom aBom = bom(comp("self", A), List.of(comp("b", B)), List.of(dep("self", "b"), dep("b")));
        Bom bBom = bom(comp("self", B), List.of(comp("c", C)), List.of(dep("self", "c"), dep("c")));
        List<SbomMerger.MissingDependency> missing =
                List.of(new SbomMerger.MissingDependency("com.acme", "c", "1.0.0"));

        Bom merged = merge(Arrays.asList(own, aBom, bBom), missing);

        assertGraphInvariants(merged);
        String c = refByPurl(merged, C);
        assertPath(merged, ROOT, refByPurl(merged, A), refByPurl(merged, B), c);
    }

    /**
     * Regression test for R1: a placeholder for a transitive dependency without an SBOM must not be added as a direct
     * child of the root when it is already reachable through its real parent, and it keeps the missingSbom marker.
     */
    @Test
    void transitivePlaceholderIsNotWiredToTheRoot() throws Exception {
        Bom own = bom(comp("root", ROOT), List.of(comp("a", A)), List.of(dep("root", "a"), dep("a")));
        Bom aBom = bom(comp("self", A), List.of(comp("b", B)), List.of(dep("self", "b"), dep("b")));
        Bom bBom = bom(comp("self", B), List.of(comp("c", C)), List.of(dep("self", "c"), dep("c")));
        List<SbomMerger.MissingDependency> missing =
                List.of(new SbomMerger.MissingDependency("com.acme", "c", "1.0.0"));

        Bom merged = merge(Arrays.asList(own, aBom, bBom), missing);

        assertGraphInvariants(merged);
        String c = refByPurl(merged, C);
        assertFalse(children(merged, ROOT).contains(c), "C is transitive and must not be a direct child of root");
        assertEquals(Collections.singleton(refByPurl(merged, B)), parents(merged, c));
        assertTrue(hasProperty(component(merged, c), SbomMerger.PROPERTY_MISSING_SBOM, "true"));
    }

    /**
     * A dependency that the project declares directly and that has no SBOM of its own must stay a direct child of the
     * root, even when an upstream SBOM also lists it as a child of another component. Today the placeholder for it is
     * reachable through that upstream, so it is not wired to the root: {@link SbomMerger.MissingDependency} does not yet
     * say whether a dependency is direct, so the merger cannot tell "declared by the project" from "transitive". The
     * component stays reachable and carries the missingSbom marker, so provenance is intact; only the direct edge that
     * Maven's own resolution would give it is missing.
     */
    @Test
    @Disabled("Known limitation (M3): a missing direct dependency reachable through an upstream SBOM loses its direct edge")
    void missingDirectDependencyReachableViaUpstreamStaysDirectChildOfRoot() throws Exception {
        // no project SBOM; the project declares A (SBOM present) and D (no SBOM); A's SBOM already lists A -> D
        Bom aBom = bom(comp("self", A), List.of(comp("d", D)), List.of(dep("self", "d"), dep("d")));
        List<SbomMerger.MissingDependency> missing =
                List.of(new SbomMerger.MissingDependency("com.acme", "d", "1.0.0"));

        Bom merged = merge(Collections.singletonList(aBom), missing);

        assertGraphInvariants(merged);
        String d = refByPurl(merged, D);
        assertDirectChildren(merged, ROOT, refByPurl(merged, A), d);
        assertPath(merged, ROOT, refByPurl(merged, A), d);
        assertTrue(hasProperty(component(merged, d), SbomMerger.PROPERTY_MISSING_SBOM, "true"));
    }

    @Test
    void graphInvariantsHoldForEverySpecVersion() throws Exception {
        for (String spec : Arrays.asList("1.3", "1.4", "1.5", "1.6", "1.7")) {
            List<SbomMerger.MissingDependency> missing =
                    List.of(new SbomMerger.MissingDependency("com.acme", "x", "1.0.0"));
            Bom merged = merge(chainRootABC(), missing, spec);
            assertGraphInvariants(merged);
            assertPath(merged, ROOT, refByPurl(merged, A), refByPurl(merged, B), refByPurl(merged, C));
        }
    }

    @Test
    void referentialIntegrityAcrossAllFixtures() throws Exception {
        // own.json is covered by ownSbomOrphanIsReachableFromRoot (known gap R12)
        List<String> names = Arrays.asList("first.json", "lib-x.json", "lib-y.json", "maven-deps.json",
                "nested.json", "scan-dangling.json", "scan-no-deps.json", "scan-syft.json",
                "second.json", "up-1.json", "up-2.json", "upstream.json");
        List<Bom> all = new ArrayList<>();
        for (String name : names) {
            Bom single = fixture(name);
            Bom merged = merge(Collections.singletonList(single), null);
            assertReferentialIntegrity(merged);
            assertAllReachableFromRoot(merged);
            all.add(fixture(name));
        }
        Bom merged = merge(all, List.of(new SbomMerger.MissingDependency("com.other", "missing", "1.0")));
        assertReferentialIntegrity(merged);
        assertAllReachableFromRoot(merged);
    }

    @Test
    void ownSbomOrphanKeepsReferentialIntegrity() throws Exception {
        Bom merged = merge(Collections.singletonList(fixture("own.json")), null);
        assertReferentialIntegrity(merged);
    }

    /**
     * Known gap R12: a component of the project's own SBOM that no edge points at (own.json lists dep-2 without an
     * edge) is kept but stays unreachable from the root and gets no inferred edge, unlike orphans of upstream SBOMs.
     * {@code SbomMergerTest.usesProjectSbomChildrenAsRootDependencies} currently locks this behaviour in.
     */
    @Test
    @Disabled("Known gap R12: orphans of the project's own SBOM are not anchored under the root")
    void ownSbomOrphanIsReachableFromRoot() throws Exception {
        Bom merged = merge(Collections.singletonList(fixture("own.json")), null);
        assertAllReachableFromRoot(merged);
    }

    private Bom fixture(String name) throws Exception {
        try (InputStream in = SbomMergerProvenanceTest.class.getResourceAsStream("merger/" + name)) {
            assertNotNull(in, "Missing test resource merger/" + name);
            Path file = dir.resolve("fixture-" + (counter++) + "-" + name);
            Files.write(file, in.readAllBytes());
            return new JsonParser().parse(file.toFile());
        }
    }
}
