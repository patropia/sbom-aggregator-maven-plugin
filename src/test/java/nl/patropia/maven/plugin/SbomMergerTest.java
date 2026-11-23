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

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Composition;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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

    /** Parses a JSON fixture from {@code src/test/resources/nl/patropia/maven/plugin/merger/}. */
    private static Bom parseBomResource(Path dir, String fileName) throws Exception {
        try (InputStream in = SbomMergerTest.class.getResourceAsStream("merger/" + fileName)) {
            assertNotNull(in, "Missing test resource merger/" + fileName);
            return parseBom(dir, fileName, new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    private static Bom merge(List<Bom> boms, List<SbomMerger.MissingDependency> missing) {
        return SbomMerger.merge(ROOT_GROUP, ROOT_ARTIFACT, ROOT_VERSION, "1.5", boms, missing, null);
    }

    private static Bom merge(List<Bom> boms, List<SbomMerger.MissingDependency> missing,
                             String specVersion, Instant timestamp) {
        return SbomMerger.merge(ROOT_GROUP, ROOT_ARTIFACT, ROOT_VERSION, specVersion, boms, missing, timestamp);
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
        Bom libX = parseBomResource(tempDir, "lib-x.json");

        Bom libY = parseBomResource(tempDir, "lib-y.json");

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
        Bom first = parseBomResource(tempDir, "first.json");

        Bom second = parseBomResource(tempDir, "second.json");

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
        Bom ownBom = parseBomResource(tempDir, "own.json");

        // An upstream SBOM whose metadata.component must NOT become a child of the root.
        Bom upstream = parseBomResource(tempDir, "upstream.json");

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
        Bom upstreamOne = parseBomResource(tempDir, "up-1.json");

        Bom upstreamTwo = parseBomResource(tempDir, "up-2.json");

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
        Bom bom = parseBomResource(tempDir, "nested.json");

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
                () -> SbomMerger.merge(null, "root", "1.0.0", "1.5", null, null, null));
        assertThrows(NullPointerException.class,
                () -> SbomMerger.merge("com.acme", null, "1.0.0", "1.5", null, null, null));
        assertThrows(NullPointerException.class,
                () -> SbomMerger.merge("com.acme", "root", null, "1.5", null, null, null));
    }

    // ------------------------------------------------------------------ M2: services, compositions, determinism

    private static final String MISSING_PURL = "pkg:maven/com.x/dep@2.0";

    private static List<SbomMerger.MissingDependency> oneMissing() {
        return new ArrayList<>(Collections.singletonList(new SbomMerger.MissingDependency("com.x", "dep", "2.0")));
    }

    @Test
    void deduplicatesServicesRenamesClashingRefsAndHoistsNestedServices(@TempDir Path dir) throws Exception {
        Bom a = parseBom(dir, "a.json", "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,"
                + "\"metadata\":{\"component\":{\"type\":\"library\",\"bom-ref\":\"lib-a\",\"group\":\"com.a\","
                + "\"name\":\"lib-a\",\"version\":\"1\"}},"
                + "\"components\":[{\"type\":\"library\",\"bom-ref\":\"clash\",\"group\":\"com.a\",\"name\":\"util\","
                + "\"version\":\"1\"}],"
                + "\"services\":[{\"bom-ref\":\"svc\",\"group\":\"com.x\",\"name\":\"api\",\"version\":\"1\","
                + "\"services\":[{\"bom-ref\":\"inner\",\"name\":\"inner\",\"version\":\"1\"}]}]}");
        Bom b = parseBom(dir, "b.json", "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,"
                + "\"metadata\":{\"component\":{\"type\":\"library\",\"bom-ref\":\"lib-b\",\"group\":\"com.b\","
                + "\"name\":\"lib-b\",\"version\":\"1\"}},"
                + "\"services\":[{\"bom-ref\":\"svc-b\",\"group\":\"com.x\",\"name\":\"api\",\"version\":\"1\","
                + "\"description\":\"from b\"},"
                + "{\"bom-ref\":\"clash\",\"name\":\"other\",\"version\":\"2\"}]}");

        Bom merged = merge(Arrays.asList(a, b), null);

        List<Service> services = merged.getServices();
        assertNotNull(services);
        assertEquals(1, services.stream().filter(s -> "api".equals(s.getName())).count(),
                "the same group:name:version service must be merged into one");
        Service api = services.stream().filter(s -> "api".equals(s.getName())).findFirst().orElseThrow();
        assertEquals("svc", api.getBomRef());
        assertEquals("from b", api.getDescription(), "missing description is filled from the duplicate");

        Service inner = services.stream().filter(s -> "inner".equals(s.getName())).findFirst().orElse(null);
        assertNotNull(inner, "nested services must be hoisted to the top level");
        assertTrue(api.getServices() == null || api.getServices().isEmpty(), "nested list must be cleared");

        Service other = services.stream().filter(s -> "other".equals(s.getName())).findFirst().orElseThrow();
        assertNotEquals("clash", other.getBomRef(), "a service ref used by a component must be renamed");
        assertEquals("other@2", other.getBomRef());

        Set<String> allRefs = new HashSet<>();
        for (Component component : merged.getComponents()) {
            assertTrue(allRefs.add(component.getBomRef()), "duplicate bom-ref " + component.getBomRef());
        }
        for (Service service : services) {
            assertTrue(allRefs.add(service.getBomRef()), "duplicate bom-ref " + service.getBomRef());
        }
    }

    @Test
    void noCompositionsBeforeSpec14() {
        assertNull(merge(null, oneMissing(), "1.3", null).getCompositions());
    }

    @Test
    void noCompositionsWithoutPlaceholders() {
        assertNull(merge(null, null, "1.5", null).getCompositions());
    }

    @Test
    void compositionsDescribeIncompleteInventoryFromSpec14() {
        for (String spec : Arrays.asList("1.4", "1.5")) {
            List<Composition> compositions = merge(null, oneMissing(), spec, null).getCompositions();
            assertNotNull(compositions, "compositions expected for " + spec);
            assertEquals(2, compositions.size());
            Composition unknown = compositions.stream()
                    .filter(c -> c.getAggregate() == Composition.Aggregate.UNKNOWN).findFirst().orElseThrow();
            assertEquals(Collections.singletonList(MISSING_PURL),
                    unknown.getDependencies().stream().map(r -> r.getRef()).collect(Collectors.toList()));
            Composition incomplete = compositions.stream()
                    .filter(c -> c.getAggregate() == Composition.Aggregate.INCOMPLETE).findFirst().orElseThrow();
            assertEquals(Collections.singletonList(ROOT_PURL),
                    incomplete.getAssemblies().stream().map(r -> r.getRef()).collect(Collectors.toList()));
        }
    }

    @Test
    void fixedTimestampGivesDeterministicSerialAndTruncatedTimestamp() {
        Instant ts = Instant.parse("2024-01-01T10:00:00.789Z");
        Bom first = merge(null, oneMissing(), "1.5", ts);
        Bom second = merge(null, oneMissing(), "1.5", ts);

        assertNotNull(first.getSerialNumber());
        assertTrue(first.getSerialNumber().startsWith("urn:uuid:"));
        assertEquals(first.getSerialNumber(), second.getSerialNumber());
        assertEquals(Instant.parse("2024-01-01T10:00:00Z"), first.getMetadata().getTimestamp().toInstant());
        assertEquals(first.getMetadata().getTimestamp(), second.getMetadata().getTimestamp());
        assertEquals(first.getComponents().stream().map(Component::getBomRef).collect(Collectors.toList()),
                second.getComponents().stream().map(Component::getBomRef).collect(Collectors.toList()));
    }

    @Test
    void serialChangesWithDependencySetOrTimestamp() {
        Instant ts = Instant.parse("2024-01-01T10:00:00Z");
        String base = merge(null, oneMissing(), "1.5", ts).getSerialNumber();
        List<SbomMerger.MissingDependency> two = oneMissing();
        two.add(new SbomMerger.MissingDependency("com.y", "other", "1.0"));
        assertNotEquals(base, merge(null, two, "1.5", ts).getSerialNumber());
        assertNotEquals(base, merge(null, oneMissing(), "1.5", ts.plusSeconds(1)).getSerialNumber());
    }

    @Test
    void withoutTimestampSerialIsRandom() {
        String first = merge(null, null, "1.5", null).getSerialNumber();
        String second = merge(null, null, "1.5", null).getSerialNumber();
        assertTrue(first.startsWith("urn:uuid:"));
        assertNotEquals(first, second);
    }

    private static Bom projectBom(String supplier, String manufacturer, String licenseId) {
        Component root = new Component();
        root.setType(Component.Type.LIBRARY);
        root.setGroup(ROOT_GROUP);
        root.setName(ROOT_ARTIFACT);
        root.setVersion(ROOT_VERSION);
        root.setPurl(ROOT_PURL);
        root.setBomRef(ROOT_PURL);
        org.cyclonedx.model.Metadata metadata = new org.cyclonedx.model.Metadata();
        metadata.setComponent(root);
        if (supplier != null) {
            org.cyclonedx.model.OrganizationalEntity entity = new org.cyclonedx.model.OrganizationalEntity();
            entity.setName(supplier);
            metadata.setSupplier(entity);
        }
        if (manufacturer != null) {
            org.cyclonedx.model.OrganizationalEntity entity = new org.cyclonedx.model.OrganizationalEntity();
            entity.setName(manufacturer);
            metadata.setManufacturer(entity);
        }
        if (licenseId != null) {
            org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setId(licenseId);
            org.cyclonedx.model.LicenseChoice choice = new org.cyclonedx.model.LicenseChoice();
            choice.addLicense(license);
            metadata.setLicenses(choice);
        }
        Bom bom = new Bom();
        bom.setMetadata(metadata);
        return bom;
    }

    @Test
    void enrichesRootMetadataFromProjectBom() {
        Bom merged = merge(new ArrayList<>(Collections.singletonList(
                projectBom("Acme Supplier", "Acme Mfg", "Apache-2.0"))), null);

        org.cyclonedx.model.Metadata metadata = merged.getMetadata();
        assertEquals("Acme Supplier", metadata.getSupplier().getName());
        assertEquals("Acme Mfg", metadata.getManufacturer().getName());
        assertEquals("Apache-2.0", metadata.getLicenses().getLicenses().get(0).getId());
        Component root = metadata.getComponent();
        assertEquals(Component.Type.APPLICATION, root.getType());
        assertEquals(ROOT_PURL, root.getPurl());
        assertEquals(ROOT_PURL, root.getBomRef());
    }

    @Test
    void enrichmentDoesNotOverwriteFirstValue() {
        Bom merged = merge(new ArrayList<>(Arrays.asList(
                projectBom("First", null, null),
                projectBom("Second", "Mfg", null))), null);

        assertEquals("First", merged.getMetadata().getSupplier().getName(), "first non-null value wins");
        assertEquals("Mfg", merged.getMetadata().getManufacturer().getName(), "empty values are still filled");
        assertNull(merged.getMetadata().getLicenses());
    }

    @Test
    void doesNotEnrichFromUpstreamBom() {
        Bom upstream = projectBom("Upstream", null, null);
        Component meta = upstream.getMetadata().getComponent();
        meta.setGroup("com.other");
        meta.setPurl("pkg:maven/com.other/root@1.0.0");
        meta.setBomRef("pkg:maven/com.other/root@1.0.0");

        Bom merged = merge(new ArrayList<>(Collections.singletonList(upstream)), null);

        assertNull(merged.getMetadata().getSupplier(), "only the project's own SBOM enriches the metadata");
    }

    @Test
    void placeholdersCarryMissingSbomProperty() {
        Bom merged = merge(null, oneMissing());

        Component placeholder = merged.getComponents().stream()
                .filter(c -> MISSING_PURL.equals(c.getPurl())).findFirst().orElseThrow();
        List<Property> properties = placeholder.getProperties();
        assertNotNull(properties);
        assertTrue(properties.stream().anyMatch(p -> SbomMerger.PROPERTY_MISSING_SBOM.equals(p.getName())
                        && "true".equals(p.getValue())),
                "placeholder must carry " + SbomMerger.PROPERTY_MISSING_SBOM + "=true");
    }

    // ------------------------------------------------------------------ vulnerabilities

    private static String vulnBom(String metaName, String compRef, String compName, String compVersion,
                                  String vulnsJson) {
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,"
                + "\"metadata\":{\"component\":{\"type\":\"library\",\"bom-ref\":\"pkg:maven/com.up/" + metaName
                + "@1.0\",\"group\":\"com.up\",\"name\":\"" + metaName + "\",\"version\":\"1.0\","
                + "\"purl\":\"pkg:maven/com.up/" + metaName + "@1.0\"}},"
                + "\"components\":[{\"type\":\"library\",\"bom-ref\":\"" + compRef + "\",\"group\":\"com.lib\","
                + "\"name\":\"" + compName + "\",\"version\":\"" + compVersion + "\",\"purl\":\"pkg:maven/com.lib/"
                + compName + "@" + compVersion + "\"}],"
                + "\"vulnerabilities\":" + vulnsJson + "}";
    }

    private static String vuln(String id, String source, String... refs) {
        StringBuilder affects = new StringBuilder();
        for (String ref : refs) {
            if (affects.length() > 0) {
                affects.append(',');
            }
            affects.append("{\"ref\":\"").append(ref).append("\"}");
        }
        return "{\"id\":\"" + id + "\",\"source\":{\"name\":\"" + source + "\"},\"affects\":[" + affects + "]}";
    }

    private static Set<String> componentRefs(Bom bom) {
        return bom.getComponents().stream().map(Component::getBomRef).collect(Collectors.toSet());
    }

    private static Vulnerability vulnById(Bom bom, String id) {
        return bom.getVulnerabilities().stream().filter(v -> id.equals(v.getId())).findFirst().orElse(null);
    }

    private static List<String> affectRefs(Vulnerability vulnerability) {
        return vulnerability.getAffects().stream().map(Vulnerability.Affect::getRef).collect(Collectors.toList());
    }

    @Test
    void mergesDuplicateVulnerabilitiesAndUnionsAffects(@TempDir Path tempDir) throws Exception {
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vuln("CVE-2024-0001", "NVD", "lib-x") + "]"));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "lib-y", "y", "2.0",
                "[" + vuln("CVE-2024-0001", "NVD", "lib-y") + "," + vuln("CVE-2024-0001", "GHSA", "lib-y") + "]"));

        Bom merged = merge(List.of(a, b), List.of());

        assertEquals(2, merged.getVulnerabilities().size(), "same id+source merged once, other source kept");
        Vulnerability nvd = merged.getVulnerabilities().stream()
                .filter(v -> "NVD".equals(v.getSource().getName())).findFirst().orElseThrow();
        assertEquals(List.of("lib-x", "lib-y"), affectRefs(nvd));
    }

    @Test
    void rewritesAffectsRefAfterBomRefCollision(@TempDir Path tempDir) throws Exception {
        // both SBOMs use the bom-ref "comp-1" for different components; the second one gets renamed
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "comp-1", "x", "1.0", "[]"));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "comp-1", "y", "2.0",
                "[" + vuln("CVE-2024-0002", "NVD", "comp-1") + "]"));

        Bom merged = merge(List.of(a, b), List.of());

        String renamed = componentByName(merged, "y").getBomRef();
        assertNotEquals("comp-1", renamed, "second component must have been renamed");
        assertEquals(List.of(renamed), affectRefs(vulnById(merged, "CVE-2024-0002")));
    }

    @Test
    void dropsDanglingAffectsRefsAndEmptyVulnerabilities(@TempDir Path tempDir) throws Exception {
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vuln("CVE-2024-0003", "NVD", "lib-x", "does-not-exist") + ","
                        + vuln("CVE-2024-0004", "NVD", "nowhere") + "]"));

        Bom merged = merge(List.of(a), List.of());

        assertEquals(1, merged.getVulnerabilities().size());
        assertEquals(List.of("lib-x"), affectRefs(vulnById(merged, "CVE-2024-0003")));
        assertTrue(componentRefs(merged).containsAll(affectRefs(vulnById(merged, "CVE-2024-0003"))));
    }

    @Test
    void emitsNoVulnerabilitiesForSpec13(@TempDir Path tempDir) throws Exception {
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vuln("CVE-2024-0005", "NVD", "lib-x") + "]"));

        Bom merged = merge(List.of(a), List.of(), "1.3", null);

        assertNull(merged.getVulnerabilities());
    }

    @Test
    void emitsNoVulnerabilitiesWhenDisabled(@TempDir Path tempDir) throws Exception {
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vuln("CVE-2024-0006", "NVD", "lib-x") + "]"));

        Bom merged = SbomMerger.merge(ROOT_GROUP, ROOT_ARTIFACT, ROOT_VERSION, "1.6", List.of(a), List.of(),
                null, false);

        assertNull(merged.getVulnerabilities());
    }

    @Test
    void vulnerabilityOrderIsDeterministic(@TempDir Path tempDir) throws Exception {
        String vulns = "[" + vuln("CVE-2024-0009", "NVD", "lib-x") + "," + vuln("CVE-2024-0001", "OSV", "lib-x")
                + "," + vuln("CVE-2024-0001", "GHSA", "lib-x") + "]";
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0", vulns));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "lib-y", "y", "2.0",
                "[" + vuln("CVE-2024-0009", "NVD", "lib-y") + "]"));

        Bom merged = merge(List.of(b, a), List.of());

        List<String> order = merged.getVulnerabilities().stream()
                .map(v -> v.getId() + "/" + v.getSource().getName()).collect(Collectors.toList());
        assertEquals(List.of("CVE-2024-0001/GHSA", "CVE-2024-0001/OSV", "CVE-2024-0009/NVD"), order);
        assertEquals(List.of("lib-x", "lib-y"), affectRefs(vulnById(merged, "CVE-2024-0009")));
    }

    /** Builds a vulnerability JSON object with an optional bom-ref and optional version ranges. */
    private static String vulnWithVersions(String bomRef, String id, String source, String ref, String versionsJson) {
        return "{"
                + (bomRef == null ? "" : "\"bom-ref\":\"" + bomRef + "\",")
                + "\"id\":\"" + id + "\",\"source\":{\"name\":\"" + source + "\"},"
                + "\"affects\":[{\"ref\":\"" + ref + "\""
                + (versionsJson == null ? "" : ",\"versions\":" + versionsJson)
                + "}]}";
    }

    private static List<String> versionKeys(Vulnerability.Affect affect) {
        return affect.getVersions().stream()
                .map(v -> v.getVersion() + "|" + v.getRange() + "|" + v.getStatus())
                .collect(Collectors.toList());
    }

    @Test
    void mergesRepeatedVersionRangesWithoutRepetition(@TempDir Path tempDir) throws Exception {
        // The CycloneDX Vulnerability.Version model has no equals(), so ranges from different SBOMs used to be
        // added twice. Identical ranges must collapse, distinct ones must survive.
        String nvdRanges = "[{\"version\":\"1.0.0\",\"status\":\"affected\"},"
                + "{\"range\":\"vers:generic/>=1.0.0|<2.0.0\",\"status\":\"affected\"}]";
        String osvRanges = "[{\"version\":\"1.0.0\",\"status\":\"affected\"},"
                + "{\"range\":\"vers:generic/>=1.0.0|<2.0.0\",\"status\":\"affected\"},"
                + "{\"version\":\"1.0.0\",\"status\":\"unaffected\"}]";
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vulnWithVersions(null, "CVE-2024-0010", "NVD", "lib-x", nvdRanges) + "]"));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "lib-x", "x", "1.0",
                "[" + vulnWithVersions(null, "CVE-2024-0010", "NVD", "lib-x", osvRanges) + "]"));

        Bom merged = merge(List.of(a, b), List.of());

        assertEquals(1, merged.getVulnerabilities().size());
        Vulnerability vulnerability = vulnById(merged, "CVE-2024-0010");
        assertEquals(1, vulnerability.getAffects().size(), "both SBOMs describe the same merged component");
        List<String> keys = versionKeys(vulnerability.getAffects().get(0));
        assertEquals(3, keys.size(), "repeated ranges must be merged, distinct ones kept: " + keys);
        assertEquals(3, new HashSet<>(keys).size(), "no repeated ranges in the output: " + keys);
        assertTrue(vulnerability.getAffects().get(0).getVersions().stream()
                .anyMatch(v -> v.getStatus() == Vulnerability.Version.Status.UNAFFECTED));
    }

    @Test
    void keepsVulnerabilityBomRefsUnique(@TempDir Path tempDir) throws Exception {
        // Different SBOMs may use the same bom-ref for different vulnerabilities, and a vulnerability bom-ref
        // may clash with a component bom-ref. CycloneDX expects bom-refs to be unique per document.
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "lib-x", "x", "1.0",
                "[" + vulnWithVersions("vuln-1", "CVE-2024-0011", "NVD", "lib-x", null) + ","
                        + vulnWithVersions("lib-x", "CVE-2024-0012", "NVD", "lib-x", null) + "]"));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "lib-y", "y", "2.0",
                "[" + vulnWithVersions("vuln-1", "CVE-2024-0013", "NVD", "lib-y", null) + "]"));

        Bom merged = merge(List.of(a, b), List.of());

        assertEquals(3, merged.getVulnerabilities().size(), "three different ids must all be kept");
        List<String> vulnRefs = merged.getVulnerabilities().stream()
                .map(Vulnerability::getBomRef).collect(Collectors.toList());
        assertEquals(3, new HashSet<>(vulnRefs).size(), "vulnerability bom-refs must be unique: " + vulnRefs);
        assertTrue(Collections.disjoint(componentRefs(merged), new HashSet<>(vulnRefs)),
                "vulnerability bom-refs must not shadow component bom-refs: " + vulnRefs);
        assertTrue(vulnRefs.contains("vuln-1"), "the first user of a bom-ref keeps it");
    }

    @Test
    void keepsVulnerabilityBomRefsDistinctFromServiceAndRootRefs(@TempDir Path tempDir) throws Exception {
        // A vulnerability bom-ref must not shadow a service bom-ref or the bom-ref of the root component.
        String rootRef = merge(List.of(), List.of()).getMetadata().getComponent().getBomRef();
        assertNotNull(rootRef);
        String json = vulnBom("a", "lib-x", "x", "1.0",
                "[" + vulnWithVersions("svc-1", "CVE-2024-0021", "NVD", "lib-x", null) + ","
                        + vulnWithVersions(rootRef, "CVE-2024-0022", "NVD", "lib-x", null) + "]")
                .replace("\"vulnerabilities\":",
                        "\"services\":[{\"bom-ref\":\"svc-1\",\"name\":\"api\",\"version\":\"1\"}],"
                                + "\"vulnerabilities\":");
        Bom a = parseBom(tempDir, "a.json", json);

        Bom merged = merge(List.of(a), List.of());

        assertNotNull(merged.getServices());
        Set<String> taken = new HashSet<>(componentRefs(merged));
        merged.getServices().forEach(s -> taken.add(s.getBomRef()));
        taken.add(merged.getMetadata().getComponent().getBomRef());
        assertTrue(taken.contains("svc-1"), "the service keeps its bom-ref");
        List<String> vulnRefs = merged.getVulnerabilities().stream()
                .map(Vulnerability::getBomRef).collect(Collectors.toList());
        assertEquals(2, vulnRefs.size());
        assertTrue(Collections.disjoint(taken, new HashSet<>(vulnRefs)),
                "vulnerability bom-refs must not shadow service or root bom-refs: " + vulnRefs);
    }

    @Test
    void mergesVulnerabilitiesOfDifferentComponentsThatShareABomRef(@TempDir Path tempDir) throws Exception {
        // Two dependency SBOMs use the same bom-ref for different components; each vulnerability must follow its
        // own component to the renamed bom-ref instead of being merged into a single affects entry.
        Bom a = parseBom(tempDir, "a.json", vulnBom("a", "comp-1", "x", "1.0",
                "[" + vuln("CVE-2024-0014", "NVD", "comp-1") + "]"));
        Bom b = parseBom(tempDir, "b.json", vulnBom("b", "comp-1", "y", "2.0",
                "[" + vuln("CVE-2024-0014", "NVD", "comp-1") + "]"));

        Bom merged = merge(List.of(a, b), List.of());

        Vulnerability vulnerability = vulnById(merged, "CVE-2024-0014");
        String refX = componentByName(merged, "x").getBomRef();
        String refY = componentByName(merged, "y").getBomRef();
        assertNotEquals(refX, refY, "the clashing components must have distinct bom-refs");
        assertEquals(2, vulnerability.getAffects().size(), "one affects entry per resolved component");
        assertEquals(List.of(refX, refY).stream().sorted().collect(Collectors.toList()),
                affectRefs(vulnerability), "each affects ref must follow its own component");
    }
}
