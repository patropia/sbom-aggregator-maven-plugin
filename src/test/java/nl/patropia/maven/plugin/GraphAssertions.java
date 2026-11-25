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
import org.cyclonedx.model.Dependency;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Graph invariants for an aggregated CycloneDX BOM, used to verify that dependency provenance survives
 * merging: every reference resolves, bom-refs are unique, and every component can be traced back to
 * {@code metadata.component.bom-ref}.
 */
final class GraphAssertions {

    private GraphAssertions() {
    }

    /** All bom-refs of the BOM: the metadata component plus every component. */
    static Set<String> knownRefs(Bom bom) {
        Set<String> known = new LinkedHashSet<>();
        known.add(rootRef(bom));
        if (bom.getComponents() != null) {
            for (Component component : bom.getComponents()) {
                known.add(component.getBomRef());
            }
        }
        return known;
    }

    static String rootRef(Bom bom) {
        assertNotNull(bom.getMetadata(), "metadata must be present");
        assertNotNull(bom.getMetadata().getComponent(), "metadata.component must be present");
        String ref = bom.getMetadata().getComponent().getBomRef();
        assertNotNull(ref, "metadata.component.bom-ref must be present");
        return ref;
    }

    /** The {@code ref -> dependsOn} adjacency of the BOM, in document order. */
    static Map<String, Set<String>> adjacency(Bom bom) {
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        if (bom.getDependencies() == null) {
            return graph;
        }
        for (Dependency dependency : bom.getDependencies()) {
            Set<String> children = graph.computeIfAbsent(dependency.getRef(), k -> new LinkedHashSet<>());
            if (dependency.getDependencies() != null) {
                for (Dependency child : dependency.getDependencies()) {
                    children.add(child.getRef());
                }
            }
        }
        return graph;
    }

    /** Direct children ({@code dependsOn}) of {@code ref}; empty when it has no entry. */
    static Set<String> children(Bom bom, String ref) {
        return adjacency(bom).getOrDefault(ref, Collections.emptySet());
    }

    /**
     * Referential integrity: bom-refs are present and unique, every {@code ref} and {@code dependsOn} target
     * resolves to the metadata component or a component, each ref has exactly one dependency entry, no entry
     * repeats a child, and every component (and the root) has a dependency entry.
     */
    static void assertReferentialIntegrity(Bom bom) {
        String root = rootRef(bom);
        Set<String> known = new HashSet<>();
        known.add(root);
        if (bom.getComponents() != null) {
            for (Component component : bom.getComponents()) {
                assertNotNull(component.getBomRef(), "component without bom-ref: " + component.getName());
                assertTrue(known.add(component.getBomRef()), "duplicate bom-ref: " + component.getBomRef());
            }
        }
        assertNotNull(bom.getDependencies(), "dependencies must be present");
        Set<String> entries = new HashSet<>();
        for (Dependency dependency : bom.getDependencies()) {
            String ref = dependency.getRef();
            assertTrue(known.contains(ref), "dependency entry references unknown bom-ref: " + ref);
            assertTrue(entries.add(ref), "more than one dependency entry for: " + ref);
            if (dependency.getDependencies() != null) {
                Set<String> seen = new HashSet<>();
                for (Dependency child : dependency.getDependencies()) {
                    assertTrue(known.contains(child.getRef()),
                            "dangling dependsOn target " + child.getRef() + " of " + ref);
                    assertTrue(seen.add(child.getRef()), "duplicate dependsOn " + child.getRef() + " of " + ref);
                }
            }
        }
        for (String ref : known) {
            assertTrue(entries.contains(ref), "no dependency entry for: " + ref);
        }
    }

    /** Refs reachable from {@code start} (inclusive) following {@code dependsOn} edges. */
    static Set<String> reachableFrom(Bom bom, String start) {
        Map<String, Set<String>> graph = adjacency(bom);
        Set<String> seen = new LinkedHashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(start);
        seen.add(start);
        while (!queue.isEmpty()) {
            for (String child : graph.getOrDefault(queue.poll(), Collections.emptySet())) {
                if (seen.add(child)) {
                    queue.add(child);
                }
            }
        }
        return seen;
    }

    /** Every component must be reachable from {@code metadata.component.bom-ref}: nothing is orphaned. */
    static void assertAllReachableFromRoot(Bom bom) {
        Set<String> reachable = reachableFrom(bom, rootRef(bom));
        Set<String> orphans = new TreeSet<>(knownRefs(bom));
        orphans.removeAll(reachable);
        assertTrue(orphans.isEmpty(), "components not reachable from the root: " + orphans);
    }

    /** Each consecutive pair of {@code refs} must be a direct {@code dependsOn} edge. */
    static void assertPath(Bom bom, String... refs) {
        Map<String, Set<String>> graph = adjacency(bom);
        for (int i = 0; i + 1 < refs.length; i++) {
            Set<String> children = graph.getOrDefault(refs[i], Collections.emptySet());
            if (!children.contains(refs[i + 1])) {
                fail("missing edge " + refs[i] + " -> " + refs[i + 1] + " on path " + Arrays.toString(refs)
                        + "; children of " + refs[i] + ": " + children);
            }
        }
    }

    /** The direct children of {@code ref} must be exactly {@code expected} (order ignored). */
    static void assertDirectChildren(Bom bom, String ref, String... expected) {
        assertEquals(new TreeSet<>(Arrays.asList(expected)), new TreeSet<>(children(bom, ref)),
                "direct children of " + ref);
    }

    /** All refs with an edge to {@code ref}. */
    static Set<String> parents(Bom bom, String ref) {
        Set<String> result = new TreeSet<>();
        for (Map.Entry<String, Set<String>> entry : adjacency(bom).entrySet()) {
            if (entry.getValue().contains(ref)) {
                result.add(entry.getKey());
            }
        }
        return result;
    }

    /** The bom-ref of the only component with the given purl. */
    static String refByPurl(Bom bom, String purl) {
        List<String> matches = new ArrayList<>();
        for (Component component : bom.getComponents()) {
            if (purl.equals(component.getPurl())) {
                matches.add(component.getBomRef());
            }
        }
        assertEquals(1, matches.size(), "expected exactly one component with purl " + purl);
        return matches.get(0);
    }

    /** The component with the given bom-ref. */
    static Component component(Bom bom, String ref) {
        for (Component component : bom.getComponents()) {
            if (ref.equals(component.getBomRef())) {
                return component;
            }
        }
        fail("no component with bom-ref " + ref);
        return null;
    }
}
