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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.license.Expression;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpdxConverterTest {

    private static final Instant FIXED = Instant.parse("2024-01-01T00:00:00Z");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Component component(String bomRef, String name, String version) {
        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setBomRef(bomRef);
        component.setName(name);
        component.setVersion(version);
        return component;
    }

    private static Bom bomWithRoot() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        Component root = component("root", "app", "1.1.0");
        root.setType(Component.Type.APPLICATION);
        metadata.setComponent(root);
        bom.setMetadata(metadata);
        return bom;
    }

    private static JsonNode convert(Bom bom) throws Exception {
        return MAPPER.readTree(SpdxConverter.toJson(bom, FIXED));
    }

    private static JsonNode pkg(JsonNode doc, String spdxId) {
        for (JsonNode p : doc.path("packages")) {
            if (spdxId.equals(p.path("SPDXID").asText())) {
                return p;
            }
        }
        throw new AssertionError("package " + spdxId + " not found in " + doc);
    }

    private static Set<String> relationships(JsonNode doc) {
        Set<String> result = new HashSet<>();
        for (JsonNode r : doc.path("relationships")) {
            result.add(r.path("spdxElementId").asText() + " " + r.path("relationshipType").asText() + " "
                    + r.path("relatedSpdxElement").asText());
        }
        return result;
    }

    @Test
    void writesSpdx23Header() throws Exception {
        JsonNode doc = convert(bomWithRoot());
        assertEquals("SPDX-2.3", doc.path("spdxVersion").asText());
        assertEquals("CC0-1.0", doc.path("dataLicense").asText());
        assertEquals("SPDXRef-DOCUMENT", doc.path("SPDXID").asText());
        assertEquals("app-1.1.0", doc.path("name").asText());
        assertTrue(doc.path("documentNamespace").asText().startsWith("https://spdx.org/spdxdocs/app-1.1.0-"));
        assertEquals("2024-01-01T00:00:00Z", doc.path("creationInfo").path("created").asText());
        assertEquals("Tool: " + SbomMerger.PLUGIN_ARTIFACT_ID,
                doc.path("creationInfo").path("creators").get(0).asText());
    }

    @Test
    void fallsBackToGenericNameWithoutMetadataComponent() throws Exception {
        JsonNode doc = convert(new Bom());
        assertEquals("sbom", doc.path("name").asText());
        assertFalse(doc.has("packages"));
        assertFalse(doc.has("relationships"));
    }

    @Test
    void outputIsReproducibleForFixedInstant() throws Exception {
        File file = new File(getClass().getResource("diff/current.json").toURI());
        Bom bom = new SbomInputReader(10L * 1024 * 1024).read(file);
        String first = SpdxConverter.toJson(bom, FIXED);
        String second = SpdxConverter.toJson(new SbomInputReader(10L * 1024 * 1024).read(file), FIXED);
        assertEquals(first, second);
        String digest = "content";
        assertEquals(SpdxConverter.documentNamespace("app", FIXED, digest),
                SpdxConverter.documentNamespace("app", FIXED, digest));
        assertNotEquals(SpdxConverter.documentNamespace("app", FIXED, digest),
                SpdxConverter.documentNamespace("app", FIXED.plusSeconds(1), digest));
    }

    @Test
    void namespaceIsUniquePerDocumentContent() throws Exception {
        Bom first = bomWithRoot();
        first.setComponents(new ArrayList<>(Arrays.asList(component("a", "a", "1"))));
        Bom second = bomWithRoot();
        second.setComponents(new ArrayList<>(Arrays.asList(component("b", "b", "1"))));

        JsonNode firstDoc = convert(first);
        JsonNode secondDoc = convert(second);
        assertEquals(firstDoc.path("name").asText(), secondDoc.path("name").asText());
        assertEquals(firstDoc.path("creationInfo").path("created").asText(),
                secondDoc.path("creationInfo").path("created").asText());
        assertNotEquals(firstDoc.path("documentNamespace").asText(),
                secondDoc.path("documentNamespace").asText(),
                "documents that only share a name and a timestamp must not share a namespace");
        assertTrue(firstDoc.path("documentNamespace").asText().startsWith("https://spdx.org/spdxdocs/app-"),
                "the namespace must stay readable: " + firstDoc.path("documentNamespace").asText());

        // The namespace stays reproducible for the same BOM.
        assertEquals(SpdxConverter.toJson(first, FIXED), SpdxConverter.toJson(first, FIXED));
    }

    @Test
    void namespaceIsUniquePerPackagePayloadNotJustItsId() throws Exception {
        // Both components keep the bom-ref (and therefore the SPDX id), so only the package payload differs.
        Bom older = bomWithRoot();
        older.setComponents(new ArrayList<>(Arrays.asList(component("dep", "dep", "1.0.0"))));
        Bom newer = bomWithRoot();
        newer.setComponents(new ArrayList<>(Arrays.asList(component("dep", "dep", "2.0.0"))));

        JsonNode olderDoc = convert(older);
        JsonNode newerDoc = convert(newer);
        assertEquals("SPDXRef-dep", pkg(olderDoc, "SPDXRef-dep").path("SPDXID").asText());
        assertEquals("SPDXRef-dep", pkg(newerDoc, "SPDXRef-dep").path("SPDXID").asText());
        assertEquals(relationships(olderDoc), relationships(newerDoc), "the fixture must keep identical relationships");
        assertNotEquals(olderDoc.path("documentNamespace").asText(), newerDoc.path("documentNamespace").asText(),
                "a package version change must change the namespace");

        Component hashed = component("dep", "dep", "1.0.0");
        hashed.setHashes(new ArrayList<>(Arrays.asList(new Hash("SHA-256", "abc"))));
        Bom withChecksum = bomWithRoot();
        withChecksum.setComponents(new ArrayList<>(Arrays.asList(hashed)));
        assertNotEquals(olderDoc.path("documentNamespace").asText(),
                convert(withChecksum).path("documentNamespace").asText(),
                "a package checksum change must change the namespace");

        // The same payload still resolves to the same namespace, so output stays reproducible.
        assertEquals(olderDoc.path("documentNamespace").asText(), convert(older).path("documentNamespace").asText());
    }

    @Test
    void distinctLicenseNamesThatSanitiseToTheSameIdGetTheirOwnLicenseRef() throws Exception {
        Component spaced = component("spaced", "spaced", "1");
        LicenseChoice spacedChoice = new LicenseChoice();
        License mitSpace = new License();
        mitSpace.setName("MIT License");
        spacedChoice.addLicense(mitSpace);
        spaced.setLicenses(spacedChoice);

        Component slashed = component("slashed", "slashed", "1");
        LicenseChoice slashedChoice = new LicenseChoice();
        License mitSlash = new License();
        mitSlash.setName("MIT/License");
        slashedChoice.addLicense(mitSlash);
        slashed.setLicenses(slashedChoice);

        Component repeated = component("repeated", "repeated", "1");
        LicenseChoice repeatedChoice = new LicenseChoice();
        License mitAgain = new License();
        mitAgain.setName("MIT License");
        repeatedChoice.addLicense(mitAgain);
        repeated.setLicenses(repeatedChoice);

        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(spaced, slashed, repeated)));
        JsonNode doc = convert(bom);

        String first = pkg(doc, "SPDXRef-spaced").path("licenseDeclared").asText();
        String second = pkg(doc, "SPDXRef-slashed").path("licenseDeclared").asText();
        assertEquals("LicenseRef-MIT-License", first);
        assertEquals("LicenseRef-MIT-License-2", second,
                "a second licence name that sanitises to the same id must not reuse the first name");
        assertEquals(first, pkg(doc, "SPDXRef-repeated").path("licenseDeclared").asText(),
                "the same licence name must always map to the same id");

        JsonNode extracted = doc.path("hasExtractedLicensingInfos");
        assertEquals(2, extracted.size());
        Set<String> names = new HashSet<>();
        Set<String> ids = new HashSet<>();
        for (JsonNode license : extracted) {
            names.add(license.path("name").asText());
            ids.add(license.path("licenseId").asText());
        }
        assertEquals(new HashSet<>(Arrays.asList("MIT License", "MIT/License")), names);
        assertEquals(new HashSet<>(Arrays.asList("LicenseRef-MIT-License", "LicenseRef-MIT-License-2")), ids);
    }

    @Test
    void createdFallsBackToBomTimestamp() throws Exception {
        Bom bom = bomWithRoot();
        bom.getMetadata().setTimestamp(Date.from(Instant.parse("2023-05-06T07:08:09Z")));
        JsonNode doc = MAPPER.readTree(SpdxConverter.toJson(bom));
        assertEquals("2023-05-06T07:08:09Z", doc.path("creationInfo").path("created").asText());
    }

    @Test
    void rootIsDescribedAndNotDuplicated() throws Exception {
        Bom bom = bomWithRoot();
        bom.setComponents(new ArrayList<>(Arrays.asList(component("root", "app", "1.1.0"),
                component("lib", "lib", "1.0"))));
        JsonNode doc = convert(bom);
        assertEquals(2, doc.path("packages").size());
        assertTrue(relationships(doc).contains("SPDXRef-DOCUMENT DESCRIBES SPDXRef-root"));
    }

    @Test
    void nestedComponentsAreHoistedWithContains() throws Exception {
        Bom bom = bomWithRoot();
        Component parent = component("parent", "parent", "1.0");
        parent.setComponents(new ArrayList<>(Arrays.asList(component("child", "child", "2.0"))));
        bom.setComponents(new ArrayList<>(Arrays.asList(parent)));
        JsonNode doc = convert(bom);
        assertEquals(3, doc.path("packages").size());
        assertEquals("child", pkg(doc, "SPDXRef-child").path("name").asText());
        assertTrue(relationships(doc).contains("SPDXRef-parent CONTAINS SPDXRef-child"));
    }

    @Test
    void inferredEdgesBecomeContains() throws Exception {
        Bom bom = bomWithRoot();
        Component image = component("img", "image", "1");
        Component rpm = component("rpm", "bash", "5.1");
        rpm.addProperty(new org.cyclonedx.model.Property(SbomMerger.PROPERTY_INFERRED_DEPENDENCY, "true"));
        Component jar = component("jar", "jackson", "2");
        bom.setComponents(new ArrayList<>(Arrays.asList(image, rpm, jar)));
        Dependency root = new Dependency("root");
        root.addDependency(new Dependency("img"));
        Dependency img = new Dependency("img");
        img.addDependency(new Dependency("rpm"));
        img.addDependency(new Dependency("jar"));
        bom.setDependencies(new ArrayList<>(Arrays.asList(root, img)));

        Set<String> rels = relationships(convert(bom));
        assertTrue(rels.contains("SPDXRef-img CONTAINS SPDXRef-rpm"), rels.toString());
        assertFalse(rels.contains("SPDXRef-img DEPENDS_ON SPDXRef-rpm"));
        assertTrue(rels.contains("SPDXRef-img DEPENDS_ON SPDXRef-jar"));
        assertTrue(rels.contains("SPDXRef-root DEPENDS_ON SPDXRef-img"));
    }

    @Test
    void dependenciesBecomeDependsOnWithoutSelfLoopsUnknownRefsOrDuplicates() throws Exception {
        Bom bom = bomWithRoot();
        bom.setComponents(new ArrayList<>(Arrays.asList(component("a", "a", "1"), component("b", "b", "1"))));
        Dependency root = new Dependency("root");
        root.addDependency(new Dependency("a"));
        Dependency a = new Dependency("a");
        a.addDependency(new Dependency("b"));
        a.addDependency(new Dependency("a"));        // self loop
        a.addDependency(new Dependency("unknown"));  // not a component
        Dependency aAgain = new Dependency("a");
        aAgain.addDependency(new Dependency("b"));   // duplicate
        bom.setDependencies(new ArrayList<>(Arrays.asList(root, a, aAgain)));

        JsonNode doc = convert(bom);
        Set<String> rels = relationships(doc);
        assertTrue(rels.contains("SPDXRef-root DEPENDS_ON SPDXRef-a"));
        assertTrue(rels.contains("SPDXRef-a DEPENDS_ON SPDXRef-b"));
        assertFalse(rels.contains("SPDXRef-a DEPENDS_ON SPDXRef-a"));
        // DESCRIBES + 2 DEPENDS_ON, duplicates suppressed
        assertEquals(3, doc.path("relationships").size());
        for (JsonNode r : doc.path("relationships")) {
            assertFalse(r.path("relatedSpdxElement").asText().contains("unknown"));
        }
    }

    @Test
    void sanitizeKeepsOnlyAllowedCharacters() {
        assertEquals("a-b-c-1.0", SpdxConverter.sanitize("a b/c@1.0!"));
        assertEquals("pkg-maven-org.example-lib-1.0", SpdxConverter.sanitize("pkg:maven/org.example/lib@1.0"));
        assertEquals("", SpdxConverter.sanitize("@@@"));
        assertEquals("", SpdxConverter.sanitize(null));
        assertEquals("sbom", SpdxConverter.slug("///"));
    }

    @Test
    void clashingIdsGetSuffixesAndDocumentIdIsReserved() throws Exception {
        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(component("a b", "x", "1"), component("a/b", "y", "1"),
                component("DOCUMENT", "z", "1"), component(null, "", null))));
        JsonNode doc = convert(bom);
        List<String> ids = new ArrayList<>();
        for (JsonNode p : doc.path("packages")) {
            ids.add(p.path("SPDXID").asText());
        }
        assertEquals(Arrays.asList("SPDXRef-a-b", "SPDXRef-a-b-2", "SPDXRef-DOCUMENT-2", "SPDXRef-sbom"), ids);
        for (String id : ids) {
            assertTrue(id.matches("SPDXRef-[A-Za-z0-9.-]+"), id);
        }
    }

    @Test
    void mapsHashAlgorithms() throws Exception {
        assertEquals("SHA256", SpdxConverter.spdxAlgorithm("SHA-256"));
        assertEquals("SHA1", SpdxConverter.spdxAlgorithm("SHA-1"));
        assertEquals("MD5", SpdxConverter.spdxAlgorithm("md5"));
        assertEquals("SHA3-512", SpdxConverter.spdxAlgorithm("SHA3-512"));
        assertEquals("BLAKE2b-256", SpdxConverter.spdxAlgorithm("BLAKE2b-256"));
        assertEquals("BLAKE3", SpdxConverter.spdxAlgorithm("BLAKE3"));
        assertNull(SpdxConverter.spdxAlgorithm("Streebog-256"));
        assertNull(SpdxConverter.spdxAlgorithm(null));

        Bom bom = new Bom();
        Component c = component("c", "c", "1");
        c.setHashes(new ArrayList<>(Arrays.asList(new Hash("SHA-256", "abc"), new Hash("Streebog-512", "def"),
                new Hash("SHA-256", "dup"))));
        bom.setComponents(new ArrayList<>(Arrays.asList(c)));
        JsonNode checksums = pkg(convert(bom), "SPDXRef-c").path("checksums");
        assertEquals(1, checksums.size());
        assertEquals("SHA256", checksums.get(0).path("algorithm").asText());
        assertEquals("abc", checksums.get(0).path("checksumValue").asText());
    }

    @Test
    void bracketsCompoundExpressionsWhenCombiningLicenses() throws Exception {
        Component combined = component("combined", "combined", "1");
        LicenseChoice choice = new LicenseChoice();
        choice.addExpression(new Expression("MIT OR Apache-2.0"));
        License bsd = new License();
        bsd.setId("BSD-3-Clause");
        choice.addLicense(bsd);
        combined.setLicenses(choice);

        Component single = component("single", "single", "1");
        LicenseChoice singleChoice = new LicenseChoice();
        singleChoice.addExpression(new Expression("MIT OR Apache-2.0"));
        single.setLicenses(singleChoice);

        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(combined, single)));
        JsonNode doc = convert(bom);

        assertEquals("(MIT OR Apache-2.0) AND BSD-3-Clause",
                pkg(doc, "SPDXRef-combined").path("licenseDeclared").asText());
        assertEquals("MIT OR Apache-2.0", pkg(doc, "SPDXRef-single").path("licenseDeclared").asText());
    }

    @Test
    void mapsLicenses() throws Exception {
        Component byId = component("id", "id", "1");
        LicenseChoice idChoice = new LicenseChoice();
        License apache = new License();
        apache.setId("Apache-2.0");
        idChoice.addLicense(apache);
        byId.setLicenses(idChoice);

        Component byExpression = component("expr", "expr", "1");
        LicenseChoice exprChoice = new LicenseChoice();
        exprChoice.setExpression(new Expression("MIT OR Apache-2.0"));
        byExpression.setLicenses(exprChoice);

        Component byName = component("name", "name", "1");
        LicenseChoice nameChoice = new LicenseChoice();
        License custom = new License();
        custom.setName("My Custom License");
        nameChoice.addLicense(custom);
        byName.setLicenses(nameChoice);

        Component none = component("none", "none", "1");

        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(byId, byExpression, byName, none)));
        JsonNode doc = convert(bom);

        assertEquals("Apache-2.0", pkg(doc, "SPDXRef-id").path("licenseDeclared").asText());
        assertEquals("MIT OR Apache-2.0", pkg(doc, "SPDXRef-expr").path("licenseDeclared").asText());
        assertEquals("LicenseRef-My-Custom-License", pkg(doc, "SPDXRef-name").path("licenseDeclared").asText());
        assertEquals("NOASSERTION", pkg(doc, "SPDXRef-none").path("licenseDeclared").asText());
        for (JsonNode p : doc.path("packages")) {
            assertEquals("NOASSERTION", p.path("licenseConcluded").asText());
            assertEquals("NOASSERTION", p.path("copyrightText").asText());
        }
        JsonNode extracted = doc.path("hasExtractedLicensingInfos");
        assertEquals(1, extracted.size());
        assertEquals("LicenseRef-My-Custom-License", extracted.get(0).path("licenseId").asText());
        assertEquals("My Custom License", extracted.get(0).path("name").asText());
    }

    @Test
    void mapsExternalReferencesAndDownloadLocation() throws Exception {
        Component c = component("c", "c", "1");
        c.setPurl("pkg:maven/org.example/c@1");
        c.setCpe("cpe:2.3:a:example:c:1:*:*:*:*:*:*:*");
        ExternalReference website = new ExternalReference();
        website.setType(ExternalReference.Type.WEBSITE);
        website.setUrl("https://example.org");
        ExternalReference distribution = new ExternalReference();
        distribution.setType(ExternalReference.Type.DISTRIBUTION);
        distribution.setUrl("https://repo.example.org/c-1.jar");
        c.setExternalReferences(new ArrayList<>(Arrays.asList(website, distribution)));

        Component old = component("old", "old", "1");
        old.setCpe("cpe:/a:example:old:1");
        old.setCopyright("(c) Example");

        Bom bom = new Bom();
        bom.setComponents(new ArrayList<>(Arrays.asList(c, old)));
        JsonNode doc = convert(bom);

        JsonNode cPkg = pkg(doc, "SPDXRef-c");
        assertEquals("https://repo.example.org/c-1.jar", cPkg.path("downloadLocation").asText());
        JsonNode refs = cPkg.path("externalRefs");
        assertEquals("PACKAGE-MANAGER", refs.get(0).path("referenceCategory").asText());
        assertEquals("purl", refs.get(0).path("referenceType").asText());
        assertEquals("pkg:maven/org.example/c@1", refs.get(0).path("referenceLocator").asText());
        assertEquals("SECURITY", refs.get(1).path("referenceCategory").asText());
        assertEquals("cpe23Type", refs.get(1).path("referenceType").asText());

        JsonNode oldPkg = pkg(doc, "SPDXRef-old");
        assertEquals("NOASSERTION", oldPkg.path("downloadLocation").asText());
        assertEquals("cpe22Type", oldPkg.path("externalRefs").get(0).path("referenceType").asText());
        assertEquals("(c) Example", oldPkg.path("copyrightText").asText());
    }

    @Test
    void everyElementHasRequiredSpdxFields() throws Exception {
        File file = new File(getClass().getResource("diff/current.json").toURI());
        JsonNode doc = convert(new SbomInputReader(10L * 1024 * 1024).read(file));
        assertTrue(doc.path("packages").size() > 0);
        for (JsonNode p : doc.path("packages")) {
            for (String field : Arrays.asList("SPDXID", "name", "downloadLocation", "licenseConcluded",
                    "licenseDeclared", "copyrightText")) {
                assertTrue(p.hasNonNull(field), field + " missing in " + p);
            }
        }
        for (JsonNode r : doc.path("relationships")) {
            for (String field : Arrays.asList("spdxElementId", "relationshipType", "relatedSpdxElement")) {
                assertTrue(r.hasNonNull(field), field + " missing in " + r);
            }
        }
    }

    @Test
    void rejectsNullBom() {
        assertThrows(IllegalArgumentException.class, () -> SpdxConverter.toSpdx(null, FIXED));
    }
}
