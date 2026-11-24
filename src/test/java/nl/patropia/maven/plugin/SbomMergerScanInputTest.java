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
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Disabled;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Characterisation tests for scanner-style (Syft/Trivy) CycloneDX input: jar purls with {@code ?type=jar}
 * and no group, rpm purls with qualifiers, generic purls, scans without dependencies and duplicate purls.
 * Maven purls are matched on their canonical key, so a scanned jar merges with the Maven component.
 * Disabled tests describe known gaps and the desired behaviour.
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
        return byName(bom, name).get(0);
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
        assertEquals(Set.of(byPurl(bom, JAR_PURL).getBomRef(), byPurl(bom, RPM_X86).getBomRef()),
                childrenOf(bom, scanRef));
    }

    @Test
    void scanWithoutDependenciesLeavesOrphans() throws Exception {
        Bom bom = merge("scan-no-deps.json");
        assertTrue(childrenOf(bom, scanRoot(bom, "app2").getBomRef()).isEmpty());
        Set<String> reachable = reachableFromRoot(bom);
        for (String purl : Arrays.asList(JAR_PURL, RPM_X86, RPM_ARM, "pkg:generic/busybox@1.36.1")) {
            assertFalse(reachable.contains(byPurl(bom, purl).getBomRef()), purl + " is currently orphaned");
        }
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

    @Test
    void jarFromScanShouldMergeWithMavenComponent() throws Exception {
        Bom bom = merge("maven-deps.json", "scan-syft.json");
        assertEquals(1, byName(bom, "jackson-databind").size());
    }

    @Test
    @Disabled("gap: orphan components of a scan without dependencies should hang under the scan's metadata.component")
    void orphansShouldHangUnderScanRoot() throws Exception {
        Bom bom = merge("scan-no-deps.json");
        assertEquals(4, childrenOf(bom, scanRoot(bom, "app2").getBomRef()).size());
    }

    @Test
    @Disabled("gap: every merged component should be reachable from the root")
    void everyComponentReachableFromRoot() throws Exception {
        Bom bom = merge("scan-syft.json");
        Set<String> reachable = reachableFromRoot(bom);
        for (Component c : bom.getComponents()) {
            assertTrue(reachable.contains(c.getBomRef()), c.getBomRef() + " unreachable");
        }
    }
}
