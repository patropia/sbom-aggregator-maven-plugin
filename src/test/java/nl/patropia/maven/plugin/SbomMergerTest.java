package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link SbomMerger}. They exercise the documented behaviour: root metadata, global
 * de-duplication, per-SBOM bom-ref scoping, nested component hoisting, root wiring, placeholders and
 * the absence of dangling references.
 */
class SbomMergerTest {

    private static final String ROOT_GROUP = "com.acme";
    private static final String ROOT_ARTIFACT = "root";
    private static final String ROOT_VERSION = "1.0.0";
    private static final String ROOT_PURL = "pkg:maven/com.acme/root@1.0.0";

    // ------------------------------------------------------------------ fixtures

    private static Bom parseBom(Path dir, String fileName, String json) throws Exception {
        Path file = dir.resolve(fileName);
        Files.writeString(file, json, StandardCharsets.UTF_8);
        return new JsonParser().parse(file.toFile());
    }

    private static Bom merge(List<Bom> boms, List<SbomMerger.MissingDependency> missing) {
        return SbomMerger.merge(ROOT_GROUP, ROOT_ARTIFACT, ROOT_VERSION, boms, missing);
    }

    private static Component componentByName(Bom bom, String name) {
        return bom.getComponents().stream()
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElse(null);
    }

    private static long countByName(Bom bom, String name) {
        return bom.getComponents().stream().filter(c -> name.equals(c.getName())).count();
    }

    private static Dependency entry(Bom bom, String ref) {
        return bom.getDependencies().stream()
                .filter(d -> ref.equals(d.getRef()))
                .findFirst()
                .orElse(null);
    }

    private static Set<String> childrenOf(Bom bom, String ref) {
        Dependency dependency = entry(bom, ref);
        if (dependency == null || dependency.getDependencies() == null) {
            return new LinkedHashSet<>();
        }
        return dependency.getDependencies().stream().map(Dependency::getRef)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static Set<String> refs(Component... components) {
        Set<String> result = new LinkedHashSet<>();
        for (Component component : components) {
            result.add(component.getBomRef());
        }
        return result;
    }

    /** Every reference in the graph must point at the root, a component or a placeholder. */
    private static void assertNoDanglingReferences(Bom bom) {
        assertNotNull(bom.getMetadata(), "metadata must be present");
        assertNotNull(bom.getMetadata().getComponent(), "root component must be present");
        Set<String> known = new HashSet<>();
        known.add(bom.getMetadata().getComponent().getBomRef());
        for (Component component : bom.getComponents()) {
            known.add(component.getBomRef());
        }
        for (Dependency dependency : bom.getDependencies()) {
            assertTrue(known.contains(dependency.getRef()),
                    "dependency entry references unknown bom-ref: " + dependency.getRef());
            if (dependency.getDependencies() != null) {
                for (Dependency child : dependency.getDependencies()) {
                    assertTrue(known.contains(child.getRef()),
                            "dangling child reference: " + child.getRef());
                }
            }
        }
    }

    // ------------------------------------------------------------------ tests

    @Test
    void buildsRootMetadataAndRootDependencyEntry() {
        Bom merged = merge(null, null);

        Component root = merged.getMetadata().getComponent();
        assertNotNull(root);
        assertEquals(Component.Type.APPLICATION, root.getType());
        assertEquals(ROOT_GROUP, root.getGroup());
        assertEquals(ROOT_ARTIFACT, root.getName());
        assertEquals(ROOT_VERSION, root.getVersion());
        assertEquals(ROOT_PURL, root.getPurl());
        assertEquals(ROOT_PURL, root.getBomRef(), "root bom-ref must be the root purl");

        assertNotNull(merged.getComponents());
        assertTrue(merged.getComponents().isEmpty(), "root must not be repeated in components");

        assertNotNull(merged.getDependencies());
        assertNotNull(entry(merged, ROOT_PURL), "root must have its own dependency entry");
        assertTrue(childrenOf(merged, ROOT_PURL).isEmpty());
        assertNoDanglingReferences(merged);
    }

    @Test
    void keepsComponentsThatReuseABomRefInDifferentBoms(@TempDir Path tempDir) throws Exception {
        // Two different upstream SBOMs both use the bom-ref "comp-1"; the second one also contains a
        // self-loop and a reference to a component that does not exist.
        Bom libX = parseBom(tempDir, "lib-x.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "library",
                      "bom-ref": "comp-1",
                      "group": "com.acme",
                      "name": "lib-x",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/lib-x@1.0.0",
                      "components": [
                        {
                          "type": "library",
                          "bom-ref": "nested-1",
                          "group": "com.acme",
                          "name": "nested-child",
                          "version": "1.0.0",
                          "purl": "pkg:maven/com.acme/nested-child@1.0.0"
                        }
                      ]
                    }
                  },
                  "dependencies": [
                    { "ref": "comp-1", "dependsOn": [ "nested-1" ] },
                    { "ref": "nested-1" }
                  ]
                }
                """);

        Bom libY = parseBom(tempDir, "lib-y.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "library",
                      "bom-ref": "comp-1",
                      "group": "com.other",
                      "name": "lib-y",
                      "version": "2.0.0",
                      "purl": "pkg:maven/com.other/lib-y@2.0.0"
                    }
                  },
                  "dependencies": [
                    { "ref": "comp-1", "dependsOn": [ "comp-1", "does-not-exist" ] }
                  ]
                }
                """);

        Bom merged = merge(Arrays.asList(libX, libY), null);

        Component mergedX = componentByName(merged, "lib-x");
        Component mergedY = componentByName(merged, "lib-y");
        Component nested = componentByName(merged, "nested-child");
        assertNotNull(mergedX, "lib-x must be kept");
        assertNotNull(mergedY, "lib-y must be kept even though it reuses lib-x's bom-ref");
        assertNotNull(nested, "nested component must be hoisted to the top level");

        assertEquals(3, merged.getComponents().size(), "exactly lib-x, lib-y and nested-child");
        assertNotEquals(mergedX.getBomRef(), mergedY.getBomRef(),
                "components must get distinct bom-refs");
        assertEquals("comp-1", mergedX.getBomRef(), "the first SBOM keeps the original bom-ref");
        assertEquals("pkg:maven/com.other/lib-y@2.0.0", mergedY.getBomRef(),
                "the clashing component falls back to its purl");
        assertEquals(1, countByName(merged, "nested-child"), "nested component must appear once");

        assertTrue(mergedX.getComponents() == null || mergedX.getComponents().isEmpty(),
                "nested components are hoisted out of the parent");
        assertEquals(Collections.singleton(nested.getBomRef()), childrenOf(merged, mergedX.getBomRef()),
                "lib-x must still depend on its nested component");

        // self-loop and the unknown reference are dropped
        assertEquals(Collections.emptySet(), childrenOf(merged, mergedY.getBomRef()));

        // the root depends on both upstream metadata components and never on itself
        assertEquals(refs(mergedX, mergedY), childrenOf(merged, ROOT_PURL));
        assertFalse(childrenOf(merged, ROOT_PURL).contains(ROOT_PURL), "root must not depend on itself");
        assertNoDanglingReferences(merged);
    }

    @Test
    void deDuplicatesByPurlAndByGav(@TempDir Path tempDir) throws Exception {
        Bom first = parseBom(tempDir, "first.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "a1",
                      "name": "lib-a",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/lib-a@1.0.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "c1",
                      "group": "com.acme",
                      "name": "lib-c",
                      "version": "1.0.0"
                    }
                  ]
                }
                """);

        Bom second = parseBom(tempDir, "second.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "a2",
                      "group": "com.acme",
                      "name": "lib-a",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/lib-a@1.0.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "c2",
                      "group": "com.acme",
                      "name": "lib-c",
                      "version": "1.0.0"
                    }
                  ]
                }
                """);

        Bom merged = merge(Arrays.asList(first, second), null);

        assertEquals(2, merged.getComponents().size(), "duplicates collapse into one component each");
        assertEquals(1, countByName(merged, "lib-a"));
        assertEquals(1, countByName(merged, "lib-c"));

        Component libA = componentByName(merged, "lib-a");
        assertEquals("com.acme", libA.getGroup(),
                "fields missing from the surviving copy are filled in from the duplicate");
        assertEquals("pkg:maven/com.acme/lib-a@1.0.0", libA.getPurl());
        assertNoDanglingReferences(merged);
    }

    @Test
    void usesProjectSbomChildrenAsRootDependencies(@TempDir Path tempDir) throws Exception {
        // The project's own SBOM: metadata.component is the project itself, which depends on dep-1.
        Bom ownBom = parseBom(tempDir, "own.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "application",
                      "bom-ref": "root-ref",
                      "group": "com.acme",
                      "name": "root",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/root@1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "d1",
                      "group": "com.acme",
                      "name": "dep-1",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/dep-1@1.0.0"
                    },
                    {
                      "type": "library",
                      "bom-ref": "d2",
                      "group": "com.acme",
                      "name": "dep-2",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/dep-2@1.0.0"
                    }
                  ],
                  "dependencies": [
                    { "ref": "root-ref", "dependsOn": [ "d1" ] },
                    { "ref": "d1" }
                  ]
                }
                """);

        // An upstream SBOM whose metadata.component must NOT become a child of the root.
        Bom upstream = parseBom(tempDir, "upstream.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "library",
                      "bom-ref": "u1",
                      "group": "com.upstream",
                      "name": "upstream-lib",
                      "version": "3.0.0",
                      "purl": "pkg:maven/com.upstream/upstream-lib@3.0.0"
                    }
                  }
                }
                """);

        Bom merged = merge(Arrays.asList(upstream, ownBom), null);

        Component dep1 = componentByName(merged, "dep-1");
        Component dep2 = componentByName(merged, "dep-2");
        Component upstreamLib = componentByName(merged, "upstream-lib");
        assertNotNull(dep1);
        assertNotNull(dep2, "components from the project's own SBOM must be kept");
        assertNotNull(upstreamLib, "upstream metadata.component must be kept as a component");
        assertEquals(3, merged.getComponents().size());

        assertEquals(Collections.singleton(dep1.getBomRef()), childrenOf(merged, ROOT_PURL),
                "the root depends on the children of the project's own SBOM, not on itself");
        assertFalse(childrenOf(merged, ROOT_PURL).contains(ROOT_PURL));
        assertNoDanglingReferences(merged);
    }

    @Test
    void keepsUpstreamMetadataComponentsAndWiresThemToTheRoot(@TempDir Path tempDir) throws Exception {
        Bom upstreamOne = parseBom(tempDir, "up-1.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "library",
                      "bom-ref": "u1",
                      "group": "com.upstream",
                      "name": "upstream-one",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.upstream/upstream-one@1.0.0"
                    }
                  },
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "t1",
                      "group": "com.upstream",
                      "name": "transitive-one",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.upstream/transitive-one@1.0.0"
                    }
                  ],
                  "dependencies": [
                    { "ref": "u1", "dependsOn": [ "t1" ] }
                  ]
                }
                """);

        Bom upstreamTwo = parseBom(tempDir, "up-2.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "metadata": {
                    "component": {
                      "type": "library",
                      "bom-ref": "u2",
                      "group": "com.upstream",
                      "name": "upstream-two",
                      "version": "2.0.0",
                      "purl": "pkg:maven/com.upstream/upstream-two@2.0.0"
                    }
                  }
                }
                """);

        Bom merged = merge(Arrays.asList(upstreamOne, upstreamTwo), null);

        Component one = componentByName(merged, "upstream-one");
        Component two = componentByName(merged, "upstream-two");
        Component transitive = componentByName(merged, "transitive-one");
        assertNotNull(one);
        assertNotNull(two);
        assertNotNull(transitive);

        assertEquals(refs(one, two), childrenOf(merged, ROOT_PURL),
                "the root depends on every upstream metadata component");
        assertEquals(Collections.singleton(transitive.getBomRef()),
                childrenOf(merged, one.getBomRef()),
                "upstream dependency graphs are preserved");
        assertNoDanglingReferences(merged);
    }

    @Test
    void createsPlaceholdersForMissingDependencies() {
        List<SbomMerger.MissingDependency> missing = new ArrayList<>();
        missing.add(new SbomMerger.MissingDependency("com.other", "missing-lib", "3.0.0"));
        missing.add(new SbomMerger.MissingDependency("com.other", "missing-lib", "3.0.0"));

        Bom merged = merge(null, missing);

        assertEquals(1, merged.getComponents().size(), "identical placeholders must be de-duplicated");
        Component placeholder = merged.getComponents().get(0);
        assertEquals(Component.Type.LIBRARY, placeholder.getType());
        assertEquals("missing-lib", placeholder.getName());
        assertEquals("pkg:maven/com.other/missing-lib@3.0.0", placeholder.getPurl());
        assertEquals(placeholder.getPurl(), placeholder.getBomRef());
        assertEquals(Collections.singleton(placeholder.getBomRef()), childrenOf(merged, ROOT_PURL),
                "placeholders must be wired to the root");
        assertNoDanglingReferences(merged);
    }

    @Test
    void ignoresMalformedMissingDependencyCoordinates() {
        assertNull(SbomMerger.MissingDependency.parse(null));
        assertNull(SbomMerger.MissingDependency.parse(""));
        assertNull(SbomMerger.MissingDependency.parse("single"));
        assertNull(SbomMerger.MissingDependency.parse("group:artifact"));
        assertNull(SbomMerger.MissingDependency.parse("group::1.0.0"));

        SbomMerger.MissingDependency parsed = SbomMerger.MissingDependency.parse("g:a:1.0.0");
        assertNotNull(parsed);
        assertEquals("g", parsed.getGroupId());
        assertEquals("a", parsed.getArtifactId());
        assertEquals("1.0.0", parsed.getVersion());
        assertEquals("g:a:1.0.0", parsed.toString());

        Bom merged = merge(null, Arrays.asList(null, parsed));
        assertEquals(1, merged.getComponents().size());
        assertNoDanglingReferences(merged);
    }

    @Test
    void hoistsNestedComponentsThatAlsoAppearAtTopLevel(@TempDir Path tempDir) throws Exception {
        Bom bom = parseBom(tempDir, "nested.json", """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1,
                  "components": [
                    {
                      "type": "library",
                      "bom-ref": "parent",
                      "group": "com.acme",
                      "name": "parent-lib",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/parent-lib@1.0.0",
                      "components": [
                        {
                          "type": "library",
                          "bom-ref": "child",
                          "group": "com.acme",
                          "name": "child-lib",
                          "version": "1.0.0",
                          "purl": "pkg:maven/com.acme/child-lib@1.0.0",
                          "components": [
                            {
                              "type": "library",
                              "bom-ref": "grandchild",
                              "group": "com.acme",
                              "name": "grandchild-lib",
                              "version": "1.0.0",
                              "purl": "pkg:maven/com.acme/grandchild-lib@1.0.0"
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "type": "library",
                      "bom-ref": "child-again",
                      "group": "com.acme",
                      "name": "child-lib",
                      "version": "1.0.0",
                      "purl": "pkg:maven/com.acme/child-lib@1.0.0"
                    }
                  ]
                }
                """);

        Bom merged = merge(Collections.singletonList(bom), null);

        assertEquals(3, merged.getComponents().size(),
                "parent, child and grandchild are each emitted exactly once");
        assertEquals(1, countByName(merged, "child-lib"));
        assertEquals(1, countByName(merged, "grandchild-lib"));

        Component parent = componentByName(merged, "parent-lib");
        assertTrue(parent.getComponents() == null || parent.getComponents().isEmpty(),
                "nested lists are cleared after hoisting");
        assertNoDanglingReferences(merged);
    }

    @Test
    void rejectsNullMavenCoordinates() {
        assertThrows(NullPointerException.class,
                () -> SbomMerger.merge(null, "root", "1.0.0", null, null));
        assertThrows(NullPointerException.class,
                () -> SbomMerger.merge("com.acme", null, "1.0.0", null, null));
        assertThrows(NullPointerException.class,
                () -> SbomMerger.merge("com.acme", "root", null, null, null));
    }
}
