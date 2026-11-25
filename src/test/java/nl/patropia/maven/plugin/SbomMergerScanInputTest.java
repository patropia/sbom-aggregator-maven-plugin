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
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Property;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Characterisation tests for scanner-style (Syft/Trivy) CycloneDX input: jar purls with {@code ?type=jar}
 * and no group, rpm purls with qualifiers, generic purls, scans without dependencies and duplicate purls.
 * Maven purls are matched on their canonical key, so a scanned jar merges with the Maven component.
 * Components a scan does not link are hung under the scan's metadata.component and flagged as inferred.
 */
class SbomMergerScanInputTest {

    private static final String JAR_PURL = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0?type=jar";
    private static final String RPM_X86 = "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4";
    private static final String RPM_ARM = "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=aarch64&distro=rhel-9.4";

    @TempDir
    Path dir;

    private Bom load(String name) throws Exception {
        try (InputStream in = getClass().getResourceAsStream("merger/" + name)) {
            assertNotNull(in, "Missing test resource merger/" + name);
            Path file = dir.resolve(name);
            Files.write(file, in.readAllBytes());
            return new JsonParser().parse(file.toFile());
        }
    }

    private Bom merge(String... names) throws Exception {
        List<Bom> boms = new ArrayList<>();
        for (String name : names) {
            boms.add(load(name));
        }
        return SbomMerger.merge("com.acme", "root", "1.0.0", "1.5", boms, new ArrayList<>(), null);
    }

    private static List<Component> byName(Bom bom, String name) {
        return bom.getComponents().stream().filter(c -> name.equals(c.getName())).collect(Collectors.toList());
    }

    private static Component byPurl(Bom bom, String purl) {
        return bom.getComponents().stream().filter(c -> purl.equals(c.getPurl())).findFirst().orElse(null);
    }

    private static Set<String> childrenOf(Bom bom, String ref) {
        return bom.getDependencies().stream().filter(d -> ref.equals(d.getRef())).findFirst()
                .map(d -> d.getDependencies() == null ? new HashSet<String>()
                        : d.getDependencies().stream().map(Dependency::getRef).collect(Collectors.toSet()))
                .orElseGet(HashSet::new);
    }

    private static Set<String> reachableFromRoot(Bom bom) {
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(bom.getMetadata().getComponent().getBomRef());
        while (!queue.isEmpty()) {
            String ref = queue.poll();
            if (seen.add(ref)) {
                queue.addAll(childrenOf(bom, ref));
            }
        }
        return seen;
    }

    private static Component scanRoot(Bom bom, String name) {
        List<Component> matches = byName(bom, name);
        assertFalse(matches.isEmpty(), "no component named " + name + " in the merged SBOM");
        return matches.get(0);
    }

    private static boolean hasDependencyEntry(Bom bom, String ref) {
        return bom.getDependencies().stream().anyMatch(d -> ref.equals(d.getRef()));
    }

    @Test
    void duplicatePurlWithinScanIsMerged() throws Exception {
        Bom bom = merge("scan-syft.json");
        List<Component> jars = byName(bom, "jackson-databind");
        assertEquals(1, jars.size());
        assertEquals(Set.of(jars.get(0).getBomRef()), childrenOf(bom, byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef()));
    }

    @Test
    void rpmArchVariantsStaySeparateWithQualifiersIntact() throws Exception {
        Bom bom = merge("scan-syft.json");
        assertEquals(2, byName(bom, "openssl-libs").size());
        assertNotNull(byPurl(bom, RPM_X86));
        assertNotNull(byPurl(bom, RPM_ARM));
    }

    @Test
    void genericAndJarPurlsKeptAsIs() throws Exception {
        Bom bom = merge("scan-syft.json");
        assertNotNull(byPurl(bom, "pkg:generic/busybox@1.36.1"));
        assertNotNull(byPurl(bom, JAR_PURL));
    }

    @Test
    void scanEdgesAreTranslatedUnderScanRoot() throws Exception {
        Bom bom = merge("scan-syft.json");
        String scanRef = scanRoot(bom, "app").getBomRef();
        assertTrue(childrenOf(bom, bom.getMetadata().getComponent().getBomRef()).contains(scanRef));
        // the scan's own edges plus the inferred links for components the scan does not link (busybox, rpm-arm)
        assertEquals(Set.of(byPurl(bom, JAR_PURL).getBomRef(), byPurl(bom, RPM_X86).getBomRef(),
                byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef(), byPurl(bom, RPM_ARM).getBomRef()),
                childrenOf(bom, scanRef));
    }

    @Test
    void scanWithoutDependenciesHangsEverythingUnderScanRoot() throws Exception {
        Bom bom = merge("scan-no-deps.json");
        String scanRef = scanRoot(bom, "app2").getBomRef();
        Set<String> reachable = reachableFromRoot(bom);
        for (String purl : Arrays.asList(JAR_PURL, RPM_X86, RPM_ARM, "pkg:generic/busybox@1.36.1")) {
            Component c = byPurl(bom, purl);
            assertTrue(reachable.contains(c.getBomRef()), purl + " must be reachable");
            assertTrue(childrenOf(bom, scanRef).contains(c.getBomRef()), purl + " must hang under the scan root");
            assertTrue(isInferred(c), purl + " must be flagged as inferred");
        }
        assertTrue(unknownCompositionRefs(bom).contains(scanRef));
    }

    @Test
    void orphansKeepTheirLevelAndAreFlagged() throws Exception {
        Bom bom = merge("scan-syft.json");
        String scanRef = scanRoot(bom, "app").getBomRef();
        String busybox = byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef();
        Component jar = byPurl(bom, JAR_PURL);
        Component arm = byPurl(bom, RPM_ARM);

        assertEquals(Set.of(jar.getBomRef(), byPurl(bom, RPM_X86).getBomRef(), busybox, arm.getBomRef()),
                childrenOf(bom, scanRef));
        assertEquals(Set.of(jar.getBomRef()), childrenOf(bom, busybox));
        assertTrue(isInferred(arm));
        assertTrue(isInferred(byPurl(bom, "pkg:generic/busybox@1.36.1")));
        // components the scan already linked are not flagged
        assertFalse(isInferred(jar));
        assertFalse(isInferred(byPurl(bom, RPM_X86)));
        assertFalse(isInferred(scanRoot(bom, "app")));
        assertTrue(unknownCompositionRefs(bom).contains(scanRef));
    }

    @Test
    void orphanBelowAnotherOrphanIsNotLinkedDirectly() {
        Component top = component("top", "top", "1", "pkg:generic/top@1");
        Component below = component("below", "below", "1", "pkg:generic/below@1");
        Bom scan = bomOf(top, below);
        scan.setMetadata(new org.cyclonedx.model.Metadata());
        scan.getMetadata().setComponent(component("s", "scan", "1", "pkg:oci/scan@1"));
        Dependency topDep = new Dependency("top");
        topDep.addDependency(new Dependency("below"));
        scan.setDependencies(new ArrayList<>(Arrays.asList(topDep)));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(scan)), new ArrayList<>(), null);
        assertEquals(Set.of("top"), childrenOf(merged, "s"));
        assertEquals(Set.of("below"), childrenOf(merged, "top"));
        assertFalse(isInferred(byPurl(merged, "pkg:generic/below@1")));
    }

    @Test
    void pureCycleOfOrphansIsLinkedOnce() {
        Component a = component("a", "a", "1", "pkg:generic/a@1");
        Component b = component("b", "b", "1", "pkg:generic/b@1");
        Bom scan = bomOf(a, b);
        scan.setMetadata(new org.cyclonedx.model.Metadata());
        scan.getMetadata().setComponent(component("s", "scan", "1", "pkg:oci/scan@1"));
        Dependency da = new Dependency("a");
        da.addDependency(new Dependency("b"));
        Dependency db = new Dependency("b");
        db.addDependency(new Dependency("a"));
        scan.setDependencies(new ArrayList<>(Arrays.asList(da, db)));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(scan)), new ArrayList<>(), null);
        assertEquals(Set.of("a"), childrenOf(merged, "s"));
        Set<String> reachable = reachableFromRoot(merged);
        assertTrue(reachable.contains("a") && reachable.contains("b"));
    }

    @Test
    void orphansOfBomWithoutMetadataComponentHangUnderRoot() {
        Bom scan = bomOf(component("x", "x", "1", "pkg:generic/x@1"));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(scan)), new ArrayList<>(), null);
        String rootRef = merged.getMetadata().getComponent().getBomRef();
        assertEquals(Set.of("x"), childrenOf(merged, rootRef));
        assertTrue(isInferred(byPurl(merged, "pkg:generic/x@1")));
        // the root itself is not an anchor with unknown dependencies
        assertTrue(unknownCompositionRefs(merged).isEmpty());
    }

    @Test
    void projectBomPlusScanMakesEverythingReachable() throws Exception {
        Bom bom = merge("own.json", "scan-syft.json");
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        assertTrue(childrenOf(bom, rootRef).contains(scanRoot(bom, "app").getBomRef()));
        assertTrue(childrenOf(bom, rootRef).contains(byPurl(bom, "pkg:maven/com.acme/dep-1@1.0.0").getBomRef()));
        // the project's own SBOM stays authoritative: dep-2 is not linked by inference
        Component dep2 = byPurl(bom, "pkg:maven/com.acme/dep-2@1.0.0");
        assertFalse(isInferred(dep2));
        Set<String> reachable = reachableFromRoot(bom);
        for (Component c : bom.getComponents()) {
            if (c != dep2) {
                assertTrue(reachable.contains(c.getBomRef()), c.getBomRef() + " unreachable");
            }
        }
    }

    @Test
    void noCompositionsBeforeSpec14() throws Exception {
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.3",
                new ArrayList<>(Arrays.asList(load("scan-no-deps.json"))), new ArrayList<>(), null);
        assertTrue(bom.getCompositions() == null || bom.getCompositions().isEmpty());
        assertTrue(isInferred(byPurl(bom, RPM_ARM)));
    }

    @Test
    void mavenOnlyInputGetsNoInferredEdges() throws Exception {
        Bom bom = merge("maven-deps.json");
        for (Component c : bom.getComponents()) {
            assertFalse(isInferred(c), c.getBomRef());
        }
        assertTrue(bom.getCompositions() == null || bom.getCompositions().isEmpty());
    }

    private static boolean isInferred(Component c) {
        return c.getProperties() != null && c.getProperties().stream().anyMatch(
                p -> SbomMerger.PROPERTY_INFERRED_DEPENDENCY.equals(p.getName()) && "true".equals(p.getValue()));
    }

    private static Set<String> unknownCompositionRefs(Bom bom) {
        Set<String> refs = new HashSet<>();
        if (bom.getCompositions() != null) {
            bom.getCompositions().stream()
                    .filter(c -> c.getAggregate() == org.cyclonedx.model.Composition.Aggregate.UNKNOWN)
                    .filter(c -> c.getDependencies() != null)
                    .forEach(c -> c.getDependencies().forEach(r -> refs.add(r.getRef())));
        }
        return refs;
    }

    @Test
    void danglingAndSelfReferencesOfScanAreDropped() throws Exception {
        Bom bom = merge("scan-dangling.json");
        String scanRef = scanRoot(bom, "app3").getBomRef();
        String jarRef = byPurl(bom, JAR_PURL).getBomRef();

        // a dependsOn entry without a matching component is dropped, not carried into the graph;
        // busybox is only linked back to the scan root, so it is anchored under it by inference
        String busyboxRef = byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef();
        assertEquals(Set.of(jarRef, busyboxRef), childrenOf(bom, scanRef));
        assertFalse(hasDependencyEntry(bom, "pkg:maven/org.example/ghost@9.9.9"));
        assertFalse(childrenOf(bom, scanRef).contains("pkg:maven/org.example/ghost@9.9.9"));

        // a dependency entry whose ref is not a known component is ignored entirely
        assertFalse(hasDependencyEntry(bom, "pkg:maven/org.example/ghost-parent@9.9.9"));

        // self-loops are removed
        assertTrue(childrenOf(bom, jarRef).isEmpty());

        // an edge back to the scan's own top-level component is kept as-is
        assertEquals(Set.of(scanRef), childrenOf(bom, byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef()));
    }

    @Test
    void jarQualifierAndMissingGroupAreMerged() throws Exception {
        Bom bom = merge("maven-deps.json", "scan-syft.json");
        List<Component> jars = byName(bom, "jackson-databind");
        assertEquals(1, jars.size());
        Component jar = jars.get(0);
        // the Maven component (first input) survives with its own purl and bom-ref
        assertEquals("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0", jar.getPurl());
        assertEquals("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0", jar.getBomRef());
        assertEquals("com.fasterxml.jackson.core", jar.getGroup());
        // scan edges are redirected to the merged component
        String scanRef = scanRoot(bom, "app").getBomRef();
        assertTrue(childrenOf(bom, scanRef).contains(jar.getBomRef()));
        assertTrue(childrenOf(bom, bom.getMetadata().getComponent().getBomRef()).contains(jar.getBomRef()));
        assertEquals(Set.of(jar.getBomRef()), childrenOf(bom, byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef()));
        // rpm arch variants are not merged by the canonical key
        assertEquals(2, byName(bom, "openssl-libs").size());
    }

    @Test
    void componentsSharingOnlyANameAreNotMerged() throws Exception {
        Bom bom = merge("scan-syft.json");
        Component a = new Component();
        a.setName("same");
        a.setVersion("1.0");
        a.setPurl("pkg:npm/same@1.0");
        a.setBomRef("a");
        Component b = new Component();
        b.setName("same");
        b.setVersion("1.0");
        b.setPurl("pkg:pypi/same@1.0");
        b.setBomRef("b");
        Bom extra = new Bom();
        extra.setComponents(new ArrayList<>(Arrays.asList(a, b)));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(bom, extra)), new ArrayList<>(), null);
        assertEquals(2, byName(merged, "same").size());
    }

    @Test
    void qualifierOrderAndEncodingVariantsMergeAcrossBoms() {
        Bom first = bomOf(component("rpm-x86", "openssl-libs", "3.0.7-27.el9",
                "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4"));
        Bom second = bomOf(component("rpm-x86-again", "openssl-libs", "3.0.7-27.el9",
                "pkg:RPM/redhat/openssl-libs@3.0.7-27.el9?DISTRO=rhel%2D9.4&arch=x86_64"));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(first, second)), new ArrayList<>(), null);
        List<Component> libs = byName(merged, "openssl-libs");
        assertEquals(1, libs.size());
        // the first purl survives unchanged, the canonical key is only used for matching
        assertEquals("pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4", libs.get(0).getPurl());
    }

    @Test
    void differentArchQualifierStaysSeparateAcrossBoms() {
        Bom first = bomOf(component("rpm-x86", "openssl-libs", "3.0.7-27.el9", RPM_X86));
        Bom second = bomOf(component("rpm-arm", "openssl-libs", "3.0.7-27.el9", RPM_ARM));
        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(first, second)), new ArrayList<>(), null);
        assertEquals(2, byName(merged, "openssl-libs").size());
        assertNotNull(byPurl(merged, RPM_X86));
        assertNotNull(byPurl(merged, RPM_ARM));
    }

    private static Component component(String ref, String name, String version, String purl) {
        Component component = new Component();
        component.setBomRef(ref);
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        return component;
    }

    private static Bom bomOf(Component... components) {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(components)));
        return bom;
    }

    private static final String JACKSON_MAVEN = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0";

    /** A Maven dependency SBOM: lib -> jackson, jackson has no dependencies. */
    private static Bom mavenLibBom() {
        Bom bom = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("pkg:maven/com.acme/lib@1.0.0", "lib", "1.0.0",
                "pkg:maven/com.acme/lib@1.0.0"));
        Dependency lib = new Dependency("pkg:maven/com.acme/lib@1.0.0");
        lib.addDependency(new Dependency(JACKSON_MAVEN));
        bom.setDependencies(new ArrayList<>(Arrays.asList(lib, new Dependency(JACKSON_MAVEN))));
        return bom;
    }

    /** A scan that claims jar -> z (e.g. a shaded class) and links the jar under its image. */
    private static Bom scanClaimingJarDependency() {
        Bom bom = bomOf(component("jar", "jackson-databind", "2.17.0", JAR_PURL),
                component("z", "z", "1", "pkg:generic/z@1"));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("img", "image", "1", "pkg:oci/image@1"));
        Dependency img = new Dependency("img");
        img.addDependency(new Dependency("jar"));
        Dependency jar = new Dependency("jar");
        jar.addDependency(new Dependency("z"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(img, jar)));
        return bom;
    }

    /** A scan of a single jar: its top component has a pkg:maven purl, and it claims jackson -> z. */
    private static Bom singleJarScanClaimingJacksonDependency() {
        Bom bom = bomOf(component("jar", "jackson-databind", "2.17.0", JAR_PURL),
                component("z", "z", "1", "pkg:generic/z@1"));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("scanned", "scanned", "1.0.0",
                "pkg:maven/com.acme/scanned@1.0.0?type=jar"));
        Dependency top = new Dependency("scanned");
        top.addDependency(new Dependency("jar"));
        Dependency jar = new Dependency("jar");
        jar.addDependency(new Dependency("z"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(top, jar)));
        return bom;
    }

    @Test
    void explicitScanWithMavenTopComponentDoesNotOverrideMavenGraph() {
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(mavenLibBom())),
                new ArrayList<>(Arrays.asList(singleJarScanClaimingJacksonDependency())),
                new ArrayList<>(), null, true);
        assertEquals(1, byName(bom, "jackson-databind").size());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        String scannedRef = byName(bom, "scanned").get(0).getBomRef();
        String libRef = byPurl(bom, "pkg:maven/com.acme/lib@1.0.0").getBomRef();

        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()), "jackson's dependsOn comes from Maven only");
        assertEquals(Set.of(jackson.getBomRef()), childrenOf(bom, libRef), "Maven parent edge kept");
        assertTrue(childrenOf(bom, scannedRef).contains(jackson.getBomRef()), "scan -> jar edge kept");
        assertTrue(childrenOf(bom, scannedRef).contains(z.getBomRef()), "z re-anchored under the scan root");
        assertTrue(isInferred(z));
        assertFalse(isInferred(jackson));
        assertTrue(reachableFromRoot(bom).contains(z.getBomRef()));
        assertTrue(unknownCompositionRefs(bom).contains(scannedRef));
    }

    @Test
    void explicitScanWhoseTopComponentIsProjectRootIsNotAuthoritative() {
        Bom scan = singleJarScanClaimingJacksonDependency();
        scan.getMetadata().setComponent(component("scanned", "root", "1.0.0", "pkg:maven/com.acme/root@1.0.0"));
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(mavenLibBom())),
                new ArrayList<>(Arrays.asList(scan)),
                new ArrayList<>(), null, true);
        assertEquals(1, byName(bom, "jackson-databind").size());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()), "jackson's dependsOn comes from Maven only");
        assertTrue(isInferred(z), "scan-only edge is re-anchored and marked inferred");
        assertTrue(reachableFromRoot(bom).contains(z.getBomRef()));
    }

    /** A dependency SBOM without metadata.component: lists jackson and an unlinked shaded helper. */
    private static Bom libBomWithoutMetadata() {
        Bom bom = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN),
                component("helper", "helper", "1", "pkg:generic/helper@1"));
        Dependency jackson = new Dependency(JACKSON_MAVEN);
        jackson.addDependency(new Dependency("helper"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(jackson)));
        return bom;
    }

    /** The project's own SBOM: root -> lib. */
    private static Bom projectBom() {
        Bom bom = bomOf(component("pkg:maven/com.acme/lib@1.0.0", "lib", "1.0.0", "pkg:maven/com.acme/lib@1.0.0"));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("pkg:maven/com.acme/root@1.0.0", "root", "1.0.0",
                "pkg:maven/com.acme/root@1.0.0"));
        Dependency root = new Dependency("pkg:maven/com.acme/root@1.0.0");
        root.addDependency(new Dependency("pkg:maven/com.acme/lib@1.0.0"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(root,
                new Dependency("pkg:maven/com.acme/lib@1.0.0"))));
        return bom;
    }

    @Test
    void dependencySbomWithoutMetadataComponentIsAnchoredUnderItsOwner() {
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(projectBom(), libBomWithoutMetadata())),
                Arrays.asList(null, "pkg:maven/com.acme/lib@1.0.0"),
                null, new ArrayList<>(), null, true);
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        String libRef = byPurl(bom, "pkg:maven/com.acme/lib@1.0.0").getBomRef();
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component helper = byPurl(bom, "pkg:generic/helper@1");

        assertEquals(Set.of(libRef), childrenOf(bom, rootRef), "the root keeps only its direct dependency");
        assertEquals(Set.of(jackson.getBomRef()), childrenOf(bom, libRef), "orphan hangs under its owner");
        assertEquals(Set.of(helper.getBomRef()), childrenOf(bom, jackson.getBomRef()), "existing level kept");
        assertTrue(isInferred(jackson));
        assertFalse(isInferred(helper));
        assertTrue(unknownCompositionRefs(bom).contains(libRef));
    }

    @Test
    void withoutOwnerTheSameSbomFallsBackToTheRoot() {
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(projectBom(), libBomWithoutMetadata())),
                new ArrayList<>(), null, true);
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        Component jackson = byName(bom, "jackson-databind").get(0);
        assertTrue(childrenOf(bom, rootRef).contains(jackson.getBomRef()));
    }

    @Test
    void ownerEqualToTheRootMarksTheProjectsOwnMavenSbom() {
        // R13: the plugin passes the root purl as the owner of the project's own SBOM, so an input owned by the
        // root is the project's Maven SBOM and is authoritative for the dependsOn of what it describes; a scan's
        // guessed edge for such a component is ignored
        Bom lib = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN));
        lib.setDependencies(new ArrayList<>(Arrays.asList(new Dependency(JACKSON_MAVEN))));
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(projectBom(), lib)),
                Arrays.asList(null, "pkg:maven/com.acme/root@1.0.0"),
                new ArrayList<>(Arrays.asList(scanClaimingJarDependency())), new ArrayList<>(), null, true);
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        Component jackson = byName(bom, "jackson-databind").get(0);

        assertEquals("pkg:maven/com.acme/root@1.0.0", rootRef);
        assertTrue(reachableFromRoot(bom).contains(jackson.getBomRef()), "jackson stays reachable from the root");
        assertTrue(childrenOf(bom, jackson.getBomRef()).isEmpty(),
                "the project's own Maven SBOM describes jackson without dependencies, so the scan's edge is ignored");
        assertTrue(byName(bom, "root").stream().noneMatch(c -> !rootRef.equals(c.getBomRef())),
                "no stray component for the project");
    }

    @Test
    void unresolvableOwnerFallsBackToTheRoot() {
        // ownerPurl(...) returns null for unknown coordinates; matching one that is not part of the merged
        // SBOM must be ignored instead of failing or creating a dangling anchor
        Bom lib = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN));
        lib.setDependencies(new ArrayList<>(Arrays.asList(new Dependency(JACKSON_MAVEN))));
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(projectBom(), lib)),
                Arrays.asList(null, "pkg:maven/com.acme/not-a-dependency@1.0.0"),
                new ArrayList<>(Arrays.asList(scanClaimingJarDependency())), new ArrayList<>(), null, true);
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");

        assertTrue(reachableFromRoot(bom).contains(jackson.getBomRef()));
        assertEquals(Set.of(z.getBomRef()), childrenOf(bom, jackson.getBomRef()),
                "an owner that matches nothing leaves the file non-authoritative");
        assertNull(byPurl(bom, "pkg:maven/com.acme/not-a-dependency@1.0.0"),
                "an unmatched owner must not be added to the SBOM");
    }

    @Test
    void ownerMakesDependencySbomAuthoritativeOverScan() {
        // the dependency SBOM has no metadata.component but describes jackson (no dependencies);
        // its owner makes it a Maven SBOM, so the scan's jackson -> z claim is ignored
        Bom lib = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN));
        lib.setDependencies(new ArrayList<>(Arrays.asList(new Dependency(JACKSON_MAVEN))));
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(projectBom(), lib)),
                Arrays.asList(null, "pkg:maven/com.acme/lib@1.0.0"),
                new ArrayList<>(Arrays.asList(scanClaimingJarDependency())), new ArrayList<>(), null, true);
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()));
        assertTrue(isInferred(z));
        assertTrue(reachableFromRoot(bom).contains(z.getBomRef()));
    }

    @Test
    void componentOnlyReferencedByMavenKeepsScanDependsOn() {
        // documented behaviour: the Maven SBOM links lib -> jackson but has no dependencies entry for jackson,
        // so Maven said nothing about jackson's own dependencies and the scan's jackson -> z edge is kept
        Bom maven = mavenLibBom();
        maven.getDependencies().removeIf(d -> JACKSON_MAVEN.equals(d.getRef()));
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(maven)),
                new ArrayList<>(Arrays.asList(scanClaimingJarDependency())), new ArrayList<>(), null, true);
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        assertEquals(Set.of(z.getBomRef()), childrenOf(bom, jackson.getBomRef()));
        assertFalse(isInferred(z));
    }

    @Test
    void unmarkedScanWithMavenTopComponentKeepsLegacyHeuristic() {
        // without the explicit scan marker the pkg:maven top component makes the input authoritative (old behaviour)
        Bom bom = mergeBoms(mavenLibBom(), singleJarScanClaimingJacksonDependency());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        assertEquals(Set.of(z.getBomRef()), childrenOf(bom, jackson.getBomRef()));
        assertFalse(isInferred(z));

        Bom eightArg = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(mavenLibBom(), singleJarScanClaimingJacksonDependency())),
                new ArrayList<>(), null, true);
        Component jackson8 = byName(eightArg, "jackson-databind").get(0);
        assertEquals(Set.of(byPurl(eightArg, "pkg:generic/z@1").getBomRef()), childrenOf(eightArg, jackson8.getBomRef()));
    }

    @Test
    void explicitScanWithoutMavenInputKeepsItsOwnEdges() {
        Bom bom = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5", null,
                new ArrayList<>(Arrays.asList(singleJarScanClaimingJacksonDependency())), null, null, true);
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        assertEquals(Set.of(z.getBomRef()), childrenOf(bom, jackson.getBomRef()));
        assertFalse(isInferred(z));
    }

    private static Bom mergeBoms(Bom... boms) {
        return SbomMerger.merge("com.acme", "root", "1.0.0", "1.5",
                new ArrayList<>(Arrays.asList(boms)), new ArrayList<>(), null);
    }

    @Test
    void mavenParentKeptWhenScanAlsoListsComponent() throws Exception {
        Bom bom = merge("maven-deps.json", "scan-syft.json");
        String rootRef = bom.getMetadata().getComponent().getBomRef();
        Component jackson = byName(bom, "jackson-databind").get(0);
        assertTrue(childrenOf(bom, rootRef).contains(jackson.getBomRef()));
        assertFalse(isInferred(jackson));
        // the scan's incoming edges are kept as well
        assertTrue(childrenOf(bom, scanRoot(bom, "app").getBomRef()).contains(jackson.getBomRef()));
        assertTrue(childrenOf(bom, byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef())
                .contains(jackson.getBomRef()));
    }

    @Test
    void scanOutgoingEdgesIgnoredForMavenDescribedComponent() {
        assertMavenGraphWins(mergeBoms(mavenLibBom(), scanClaimingJarDependency()));
    }

    @Test
    void scanOutgoingEdgesIgnoredRegardlessOfInputOrder() {
        assertMavenGraphWins(mergeBoms(scanClaimingJarDependency(), mavenLibBom()));
    }

    private static void assertMavenGraphWins(Bom bom) {
        List<Component> jacksons = byName(bom, "jackson-databind");
        assertEquals(1, jacksons.size());
        Component jackson = jacksons.get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        String libRef = byPurl(bom, "pkg:maven/com.acme/lib@1.0.0").getBomRef();
        String imgRef = byPurl(bom, "pkg:oci/image@1").getBomRef();

        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()), "jackson's dependsOn comes from Maven");
        assertEquals(Set.of(jackson.getBomRef()), childrenOf(bom, libRef), "Maven parent edge kept");
        assertTrue(childrenOf(bom, imgRef).contains(jackson.getBomRef()), "scan -> jar containment edge kept");
        assertFalse(isInferred(jackson));
        assertTrue(childrenOf(bom, imgRef).contains(z.getBomRef()), "z hangs under the scan root");
        assertTrue(isInferred(z));
        assertTrue(reachableFromRoot(bom).contains(z.getBomRef()));
        assertTrue(unknownCompositionRefs(bom).contains(imgRef));
    }

    @Test
    void scanOutgoingEdgesKeptWhenNoMavenDescription() throws Exception {
        Bom bom = merge("scan-syft.json");
        Component jar = byPurl(bom, JAR_PURL);
        assertEquals(Set.of(jar.getBomRef()), childrenOf(bom, byPurl(bom, "pkg:generic/busybox@1.36.1").getBomRef()));
        Bom scanOnly = mergeBoms(scanClaimingJarDependency());
        Component z = byPurl(scanOnly, "pkg:generic/z@1");
        assertEquals(Set.of(z.getBomRef()), childrenOf(scanOnly, byPurl(scanOnly, JAR_PURL).getBomRef()));
        assertFalse(isInferred(z));
    }

    @Test
    void jarFromScanShouldMergeWithMavenComponent() throws Exception {
        Bom bom = merge("maven-deps.json", "scan-syft.json");
        assertEquals(1, byName(bom, "jackson-databind").size());
    }

    @Test
    void orphansShouldHangUnderScanRoot() throws Exception {
        Bom bom = merge("scan-no-deps.json");
        assertEquals(4, childrenOf(bom, scanRoot(bom, "app2").getBomRef()).size());
    }

    @Test
    void everyComponentReachableFromRoot() throws Exception {
        Bom bom = merge("scan-syft.json");
        Set<String> reachable = reachableFromRoot(bom);
        for (Component c : bom.getComponents()) {
            assertTrue(reachable.contains(c.getBomRef()), c.getBomRef() + " unreachable");
        }
    }

    // ------------------------------------------------------------------------------------------
    // Maven graph wins over the scan graph: edge cases around the components whose dependsOn is
    // taken from the Maven SBOM instead of from the scan.
    // ------------------------------------------------------------------------------------------

    /**
     * A Maven dependency SBOM whose root depends on jackson and on z; neither has children. z is therefore
     * already part of the Maven graph when a scan also guesses {@code jar -> z}.
     */
    private static Bom mavenLibWithZSiblingBom() {
        Component jackson = component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN);
        Component z = component("maven-z", "z", "1", "pkg:generic/z@1");
        Bom bom = bomOf(jackson, z);
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("pkg:maven/com.acme/lib@1.0.0", "lib", "1.0.0",
                "pkg:maven/com.acme/lib@1.0.0"));
        Dependency lib = new Dependency("pkg:maven/com.acme/lib@1.0.0");
        lib.addDependency(new Dependency(JACKSON_MAVEN));
        lib.addDependency(new Dependency("maven-z"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(lib, new Dependency(JACKSON_MAVEN),
                new Dependency("maven-z"))));
        return bom;
    }

    /**
     * A Maven SBOM (top component is a {@code pkg:maven} purl) that lists jackson but carries no
     * {@code dependencies} section at all, so it says nothing about anybody's children.
     */
    private static Bom mavenLibBomWithoutDependencies() {
        Bom bom = bomOf(component(JACKSON_MAVEN, "jackson-databind", "2.17.0", JACKSON_MAVEN));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("pkg:maven/com.acme/lib@1.0.0", "lib", "1.0.0",
                "pkg:maven/com.acme/lib@1.0.0"));
        return bom;
    }

    /**
     * A scan that claims a deeper chain than {@link #scanClaimingJarDependency()}: the jar bundles z and z
     * depends on w. Only the dropped edge {@code jar -> z} has to be replaced, not the level below it.
     */
    private static Bom scanClaimingChainedJarDependency() {
        Bom bom = bomOf(component("jar", "jackson-databind", "2.17.0", JAR_PURL),
                component("z", "z", "1", "pkg:generic/z@1"),
                component("w", "w", "1", "pkg:generic/w@1"));
        bom.setMetadata(new org.cyclonedx.model.Metadata());
        bom.getMetadata().setComponent(component("img", "image", "1", "pkg:oci/image@1"));
        Dependency img = new Dependency("img");
        img.addDependency(new Dependency("jar"));
        Dependency jar = new Dependency("jar");
        jar.addDependency(new Dependency("z"));
        Dependency z = new Dependency("z");
        z.addDependency(new Dependency("w"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(img, jar, z)));
        return bom;
    }

    @Test
    void scanEdgeTargetAlreadyInMavenGraphIsNotReAnchored() {
        Bom bom = mergeBoms(mavenLibWithZSiblingBom(), scanClaimingJarDependency());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        String libRef = byPurl(bom, "pkg:maven/com.acme/lib@1.0.0").getBomRef();
        String imgRef = byPurl(bom, "pkg:oci/image@1").getBomRef();

        // the scan's z merges with the Maven z instead of being added a second time
        assertEquals(1, byName(bom, "z").size());
        // the scan's guess for jackson is still dropped, the Maven parent and sibling are kept
        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()), "jackson's dependsOn comes from Maven");
        assertEquals(Set.of(jackson.getBomRef(), z.getBomRef()), childrenOf(bom, libRef));
        // z is reachable from the root through the Maven graph, so it is neither anchored twice nor flagged
        assertEquals(Set.of(jackson.getBomRef()), childrenOf(bom, imgRef),
                "an inferred link must not duplicate a Maven edge to the same component");
        assertFalse(isInferred(z));
        assertFalse(isInferred(jackson));
        assertTrue(reachableFromRoot(bom).contains(z.getBomRef()));
    }

    @Test
    void inferredAnchorKeepsTheScanLevelsBelowIt() {
        Bom bom = mergeBoms(mavenLibBom(), scanClaimingChainedJarDependency());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");
        Component w = byPurl(bom, "pkg:generic/w@1");
        String imgRef = byPurl(bom, "pkg:oci/image@1").getBomRef();

        assertEquals(Set.of(), childrenOf(bom, jackson.getBomRef()));
        // the scan's edge into the jar is kept and only z has to replace the dropped edge;
        // z -> w stays as the scan reported it
        assertEquals(Set.of(jackson.getBomRef(), z.getBomRef()), childrenOf(bom, imgRef));
        assertTrue(isInferred(z), "the component that replaces the dropped edge is flagged");
        assertEquals(Set.of(w.getBomRef()), childrenOf(bom, z.getBomRef()), "z -> w keeps its level");
        assertFalse(isInferred(w), "only the anchor target is flagged, not the subtree below it");
        Set<String> reachable = reachableFromRoot(bom);
        assertTrue(reachable.contains(z.getBomRef()) && reachable.contains(w.getBomRef()));
        assertTrue(unknownCompositionRefs(bom).contains(imgRef));
    }

    @Test
    void inferredMarkerIsAddedNextToExistingProperties() {
        Component z = component("z", "z", "1", "pkg:generic/z@1");
        z.setProperties(new ArrayList<>(List.of(new Property("scan:source", "syft"))));
        Bom scan = bomOf(component("jar", "jackson-databind", "2.17.0", JAR_PURL), z);
        scan.setMetadata(new org.cyclonedx.model.Metadata());
        scan.getMetadata().setComponent(component("img", "image", "1", "pkg:oci/image@1"));
        Dependency img = new Dependency("img");
        img.addDependency(new Dependency("jar"));
        Dependency jar = new Dependency("jar");
        jar.addDependency(new Dependency("z"));
        scan.setDependencies(new ArrayList<>(Arrays.asList(img, jar)));

        Bom bom = mergeBoms(mavenLibBom(), scan);
        Component merged = byPurl(bom, "pkg:generic/z@1");
        assertTrue(isInferred(merged));
        assertTrue(merged.getProperties().stream().anyMatch(p -> "scan:source".equals(p.getName())
                        && "syft".equals(p.getValue())),
                "existing properties must survive the inferred marker: " + merged.getProperties());
    }

    @Test
    void mavenInputWithoutDependencyGraphDoesNotSuppressScanEdges() {
        // the Maven SBOM lists jackson but has no dependencies section, so it does not describe any children;
        // the scan is the only source of that information and its edge is used
        Bom bom = mergeBoms(mavenLibBomWithoutDependencies(), scanClaimingJarDependency());
        Component jackson = byName(bom, "jackson-databind").get(0);
        Component z = byPurl(bom, "pkg:generic/z@1");

        assertEquals(1, byName(bom, "jackson-databind").size());
        assertEquals(Set.of(z.getBomRef()), childrenOf(bom, jackson.getBomRef()));
        assertFalse(isInferred(z), "an edge the scan really reported is not inferred");
    }
}
