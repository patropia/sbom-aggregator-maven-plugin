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

import nl.patropia.maven.plugin.SbomDiffReport.ChangeType;
import nl.patropia.maven.plugin.SbomDiffReport.ComponentChange;
import nl.patropia.maven.plugin.SbomDiffReport.VulnerabilityChange;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link SbomDiff}. */
class SbomDiffTest {

    private static Bom load(String name) throws Exception {
        File file = resource(name);
        return new SbomInputReader(0).read(file);
    }

    private static File resource(String name) throws URISyntaxException {
        return new File(SbomDiffTest.class.getResource("/nl/patropia/maven/plugin/diff/" + name).toURI());
    }

    private static List<String> summary(List<ComponentChange> changes) {
        return changes.stream()
                .map(c -> c.getType() + " " + c.getDisplayName() + " " + c.getBaselineVersion() + " -> "
                        + c.getCurrentVersion())
                .collect(Collectors.toList());
    }

    private static Component component(String ref, String group, String name, String version, String purl) {
        Component c = new Component();
        c.setType(Component.Type.LIBRARY);
        c.setBomRef(ref);
        c.setGroup(group);
        c.setName(name);
        c.setVersion(version);
        c.setPurl(purl);
        return c;
    }

    private static Bom bom(Component... components) {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(components)));
        return bom;
    }

    private static Vulnerability vulnerability(String id, String source, String severity, String... refs) {
        Vulnerability v = new Vulnerability();
        v.setId(id);
        if (source != null) {
            Vulnerability.Source s = new Vulnerability.Source();
            s.setName(source);
            v.setSource(s);
        }
        if (severity != null) {
            Vulnerability.Rating rating = new Vulnerability.Rating();
            rating.setSeverity(Vulnerability.Rating.Severity.fromString(severity));
            v.setRatings(new ArrayList<>(Collections.singletonList(rating)));
        }
        List<Vulnerability.Affect> affects = new ArrayList<>();
        for (String ref : refs) {
            Vulnerability.Affect affect = new Vulnerability.Affect();
            affect.setRef(ref);
            affects.add(affect);
        }
        v.setAffects(affects);
        return v;
    }

    @Test
    void reportsAddedRemovedAndChangedComponentsFromFiles() throws Exception {
        SbomDiffReport report = SbomDiff.diff(load("baseline.json"), load("current.json"));

        assertEquals(Arrays.asList(
                "ADDED com.acme:shaded null -> 5.0",
                "ADDED org.example:fresh null -> 1.0.0"), summary(report.getAddedComponents()));
        assertEquals(Collections.singletonList("REMOVED com.acme:legacy 0.9 -> null"),
                summary(report.getRemovedComponents()));
        assertEquals(Arrays.asList(
                "UPGRADED com.acme:lib-b 2.0.0 -> 2.1.0",
                "DOWNGRADED com.acme:lib-c 3.1.0 -> 3.0.0",
                "UPGRADED org.example:no-purl 1.0 -> 1.1"), summary(report.getChangedComponents()));
        // lib-a is unchanged; the root component (app 1.0.0 -> 1.1.0) is not compared
        assertEquals(1, report.getUnchangedCount());
        assertTrue(report.hasChanges());
    }

    @Test
    void keysIgnoreVersionButKeepQualifiers() throws Exception {
        SbomDiffReport report = SbomDiff.diff(load("baseline.json"), load("current.json"));
        ComponentChange libB = report.getChangedComponents().get(0);
        assertEquals("pkg:maven/com.acme/lib-b?type=jar", libB.getKey());
        ComponentChange noPurl = report.getChangedComponents().get(2);
        assertEquals("org.example:no-purl", noPurl.getKey());
    }

    @Test
    void reportsNewAndResolvedVulnerabilities() throws Exception {
        SbomDiffReport report = SbomDiff.diff(load("baseline.json"), load("current.json"));

        assertEquals(1, report.getNewVulnerabilities().size());
        VulnerabilityChange added = report.getNewVulnerabilities().get(0);
        assertEquals("CVE-2024-0003", added.getId());
        assertEquals("NVD", added.getSource());
        // the highest of the ratings wins
        assertEquals("critical", added.getSeverity());
        // affects are resolved to purls and sorted
        assertEquals(Arrays.asList("pkg:maven/com.acme/lib-c@3.0.0?type=jar",
                "pkg:maven/org.example/fresh@1.0.0?type=jar"), added.getAffects());

        assertEquals(1, report.getResolvedVulnerabilities().size());
        VulnerabilityChange resolved = report.getResolvedVulnerabilities().get(0);
        assertEquals("CVE-2020-0001", resolved.getId());
        assertEquals("high", resolved.getSeverity());
        assertEquals(Collections.singletonList("pkg:maven/com.acme/legacy@0.9?type=jar"), resolved.getAffects());
    }

    @Test
    void identicalSbomsHaveNoChanges() throws Exception {
        SbomDiffReport report = SbomDiff.diff(load("current.json"), load("current.json"));
        assertFalse(report.hasChanges());
        assertTrue(report.getAddedComponents().isEmpty());
        assertTrue(report.getRemovedComponents().isEmpty());
        assertTrue(report.getChangedComponents().isEmpty());
        assertTrue(report.getNewVulnerabilities().isEmpty());
        assertTrue(report.getResolvedVulnerabilities().isEmpty());
        assertEquals(6, report.getUnchangedCount());
    }

    @Test
    void emptySbomsAreHandled() {
        SbomDiffReport report = SbomDiff.diff(new Bom(), new Bom());
        assertFalse(report.hasChanges());
        assertEquals(0, report.getUnchangedCount());

        Bom one = bom(component("x", "g", "x", "1", "pkg:maven/g/x@1"));
        SbomDiffReport fromEmpty = SbomDiff.diff(new Bom(), one);
        assertEquals(Collections.singletonList("ADDED g:x null -> 1"), summary(fromEmpty.getAddedComponents()));
    }

    @Test
    void orderingIsDeterministicRegardlessOfInputOrder() {
        Component a = component("1", "g", "a", "1.0", "pkg:maven/g/a@1.0");
        Component b = component("2", "g", "b", "1.0", "pkg:maven/g/b@1.0");
        Component c = component("3", "g", "c", "1.0", null);
        Bom forward = bom(a, b, c);
        Bom backward = bom(component("3", "g", "c", "1.0", null),
                component("2", "g", "b", "1.0", "pkg:maven/g/b@1.0"),
                component("1", "g", "a", "1.0", "pkg:maven/g/a@1.0"));
        forward.setVulnerabilities(new ArrayList<>(Arrays.asList(
                vulnerability("CVE-2", "NVD", "low", "1"), vulnerability("CVE-1", "OSV", null, "2"),
                vulnerability("CVE-1", "NVD", "high", "3"))));
        backward.setVulnerabilities(new ArrayList<>(Arrays.asList(
                vulnerability("CVE-1", "NVD", "high", "3"), vulnerability("CVE-1", "OSV", null, "2"),
                vulnerability("CVE-2", "NVD", "low", "1"))));

        SbomDiffReport r1 = SbomDiff.diff(new Bom(), forward);
        SbomDiffReport r2 = SbomDiff.diff(new Bom(), backward);
        assertEquals(summary(r1.getAddedComponents()), summary(r2.getAddedComponents()));
        assertEquals(Arrays.asList("ADDED g:a null -> 1.0", "ADDED g:b null -> 1.0", "ADDED g:c null -> 1.0"),
                summary(r1.getAddedComponents()));
        List<String> v1 = r1.getNewVulnerabilities().stream().map(Object::toString).collect(Collectors.toList());
        List<String> v2 = r2.getNewVulnerabilities().stream().map(Object::toString).collect(Collectors.toList());
        assertEquals(v1, v2);
        assertEquals(Arrays.asList("CVE-1 (NVD) high [g:c@1.0]",
                "CVE-1 (OSV) unknown [pkg:maven/g/b@1.0]",
                "CVE-2 (NVD) low [pkg:maven/g/a@1.0]"), v1);
    }

    @Test
    void vulnerabilitiesAreKeyedByIdAndSource() {
        Component a = component("a", "g", "a", "1", "pkg:maven/g/a@1");
        Bom before = bom(a);
        before.setVulnerabilities(new ArrayList<>(Collections.singletonList(
                vulnerability("CVE-1", "NVD", "high", "a"))));
        Bom after = bom(component("a", "g", "a", "1", "pkg:maven/g/a@1"));
        after.setVulnerabilities(new ArrayList<>(Arrays.asList(
                vulnerability("CVE-1", "NVD", "high", "a"), vulnerability("CVE-1", "GHSA", "high", "a"),
                vulnerability(null, "NVD", "high", "a"))));

        SbomDiffReport report = SbomDiff.diff(before, after);
        assertEquals(1, report.getNewVulnerabilities().size());
        assertEquals("GHSA", report.getNewVulnerabilities().get(0).getSource());
        assertTrue(report.getResolvedVulnerabilities().isEmpty());
        // a vulnerability on a ref that cannot be resolved keeps the raw ref
        Bom dangling = bom();
        dangling.setVulnerabilities(new ArrayList<>(Collections.singletonList(
                vulnerability("CVE-9", null, null, "missing-ref"))));
        VulnerabilityChange v = SbomDiff.diff(new Bom(), dangling).getNewVulnerabilities().get(0);
        assertEquals("", v.getSource());
        assertEquals("unknown", v.getSeverity());
        assertEquals(Collections.singletonList("missing-ref"), v.getAffects());
    }

    @Test
    void componentsWithoutPurlFallBackToGroupNameThenBomRef() {
        Bom before = bom(component("r1", null, "plain", "1.0", null), component("only-ref", null, null, "1", null),
                component(null, null, null, null, null));
        Bom after = bom(component("r2", null, "plain", "2.0", null), component("only-ref", null, null, "2", null));
        SbomDiffReport report = SbomDiff.diff(before, after);
        assertEquals(Arrays.asList("UPGRADED plain 1.0 -> 2.0", "UPGRADED ref:only-ref 1 -> 2"),
                summary(report.getChangedComponents()));
        assertEquals("plain", report.getChangedComponents().get(0).getKey());
        assertTrue(report.getAddedComponents().isEmpty());
        assertTrue(report.getRemovedComponents().isEmpty());
    }

    @Test
    void multipleVersionsOfOneComponentAreReportedPerVersion() {
        Bom before = bom(component("1", "g", "a", "1.0", "pkg:maven/g/a@1.0"),
                component("2", "g", "a", "2.0", "pkg:maven/g/a@2.0"));
        Bom after = bom(component("1", "g", "a", "2.0", "pkg:maven/g/a@2.0"),
                component("2", "g", "a", "3.0", "pkg:maven/g/a@3.0"));
        SbomDiffReport report = SbomDiff.diff(before, after);
        assertEquals(Collections.singletonList("ADDED g:a null -> 3.0"), summary(report.getAddedComponents()));
        assertEquals(Collections.singletonList("REMOVED g:a 1.0 -> null"), summary(report.getRemovedComponents()));
        assertTrue(report.getChangedComponents().isEmpty());
    }

    @Test
    void classifyUsesMavenVersionOrdering() {
        assertEquals(ChangeType.UPGRADED, SbomDiff.classify("1.9", "1.10"));
        assertEquals(ChangeType.UPGRADED, SbomDiff.classify("1.0-SNAPSHOT", "1.0"));
        assertEquals(ChangeType.DOWNGRADED, SbomDiff.classify("2.0.0", "2.0.0-RC1"));
        assertEquals(ChangeType.CHANGED, SbomDiff.classify("", "1.0"));
        assertEquals(ChangeType.CHANGED, SbomDiff.classify("1.0", "1.0.0"));
    }

    @Test
    void missingVersionOnOneSideIsChanged() {
        Bom before = bom(component("1", "g", "a", null, "pkg:maven/g/a"));
        Bom after = bom(component("1", "g", "a", "1.0", "pkg:maven/g/a@1.0"));
        ComponentChange change = SbomDiff.diff(before, after).getChangedComponents().get(0);
        assertEquals(ChangeType.CHANGED, change.getType());
        assertNull(change.getBaselineVersion());
        assertEquals("1.0", change.getCurrentVersion());
    }

    @Test
    void stripPurlVersionKeepsQualifiersAndSubpath() {
        assertEquals("pkg:maven/g/a", SbomDiff.stripPurlVersion("pkg:maven/g/a@1.0"));
        assertEquals("pkg:maven/g/a?classifier=tests&type=jar",
                SbomDiff.stripPurlVersion("pkg:maven/g/a@1.0?classifier=tests&type=jar"));
        assertEquals("pkg:npm/%40scope/a#sub/path", SbomDiff.stripPurlVersion("pkg:npm/%40scope/a@1.2.3#sub/path"));
        assertEquals("pkg:maven/g/a", SbomDiff.stripPurlVersion("pkg:maven/g/a"));
        assertEquals("pkg:npm/@scope/a", SbomDiff.stripPurlVersion("pkg:npm/@scope/a"));
        assertEquals("pkg:npm/@scope/a", SbomDiff.stripPurlVersion("pkg:npm/@scope/a@1.0"));
    }

    @Test
    void nullArgumentsAreRejected() {
        assertThrows(NullPointerException.class, () -> SbomDiff.diff(null, new Bom()));
        assertThrows(NullPointerException.class, () -> SbomDiff.diff(new Bom(), null));
    }
}
