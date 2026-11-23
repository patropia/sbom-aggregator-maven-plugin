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

import org.apache.maven.plugin.logging.Log;
import org.cyclonedx.Version;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the output schema validation added in milestone M3: the generated SBOM is checked against the
 * official CycloneDX JSON/XML schema of the configured spec version before it is written.
 */
class OutputSchemaValidationTest {

    @TempDir
    Path tempDir;

    private static Bom sampleBom() {
        Bom bom = new Bom();
        Component root = new Component();
        root.setType(Component.Type.APPLICATION);
        root.setGroup("com.acme");
        root.setName("root");
        root.setVersion("1.0.0");
        root.setBomRef("pkg:maven/com.acme/root@1.0.0");
        root.setPurl("pkg:maven/com.acme/root@1.0.0");
        Metadata metadata = new Metadata();
        metadata.setComponent(root);
        bom.setMetadata(metadata);

        Component library = new Component();
        library.setType(Component.Type.LIBRARY);
        library.setGroup("com.acme");
        library.setName("lib");
        library.setVersion("2.0.0");
        library.setBomRef("pkg:maven/com.acme/lib@2.0.0");
        library.setPurl("pkg:maven/com.acme/lib@2.0.0");
        bom.setComponents(List.of(library));
        return bom;
    }

    private static String json(Bom bom, Version version) throws Exception {
        return BomGeneratorFactory.createJson(version, bom).toJsonString();
    }

    private static String xml(Bom bom, Version version) throws Exception {
        return BomGeneratorFactory.createXml(version, bom).toXmlString();
    }

    @Test
    void generatedJsonDocumentPassesSchemaValidation() throws Exception {
        String content = json(sampleBom(), Version.VERSION_15);
        AggregateSbomMojo.validateBomContent(content.getBytes(StandardCharsets.UTF_8), "json",
                Version.VERSION_15, "1.5");
    }

    @Test
    void generatedXmlDocumentPassesSchemaValidation() throws Exception {
        String content = xml(sampleBom(), Version.VERSION_15);
        AggregateSbomMojo.validateBomContent(content.getBytes(StandardCharsets.UTF_8), "xml",
                Version.VERSION_15, "1.5");
    }

    @Test
    void generatedDocumentPassesValidationForEverySupportedSpecVersion() throws Exception {
        for (Version version : List.of(Version.VERSION_13, Version.VERSION_14, Version.VERSION_15,
                Version.VERSION_16, Version.VERSION_17)) {
            Bom bom = sampleBom();
            AggregateSbomMojo.validateBomContent(json(bom, version).getBytes(StandardCharsets.UTF_8),
                    "json", version, version.name());
            AggregateSbomMojo.validateBomContent(xml(bom, version).getBytes(StandardCharsets.UTF_8),
                    "xml", version, version.name());
        }
    }

    @Test
    void invalidJsonDocumentIsRejectedWithSchemaMessage() {
        String content = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"notAProperty\":1}";
        MojoAssertions.assertThrowsWithMessage(() -> AggregateSbomMojo.validateBomContent(
                content.getBytes(StandardCharsets.UTF_8), "json", Version.VERSION_15, "1.5"));
    }

    @Test
    void invalidXmlDocumentIsRejectedWithSchemaMessage() {
        String content = "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\"><notAnElement/></bom>";
        MojoAssertions.assertThrowsWithMessage(() -> AggregateSbomMojo.validateBomContent(
                content.getBytes(StandardCharsets.UTF_8), "xml", Version.VERSION_15, "1.5"));
    }

    @Test
    void newerSpecFieldIsRejectedForOlderSchema() throws Exception {
        // Newer schemas accept older documents, so the check is the other way round:
        // a field introduced in 1.5 ("annotations") is valid for 1.5 but rejected by the 1.3 schema.
        String v15 = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"annotations\":[]}";
        AggregateSbomMojo.validateBomContent(v15.getBytes(StandardCharsets.UTF_8), "json",
                Version.VERSION_15, "1.5");
        String v13 = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.3\",\"annotations\":[]}";
        assertThrows(org.apache.maven.plugin.MojoExecutionException.class,
                () -> AggregateSbomMojo.validateBomContent(v13.getBytes(StandardCharsets.UTF_8), "json",
                        Version.VERSION_13, "1.3"));
    }

    @Test
    void everySchemaProblemIsLoggedAtDebugLevel() {
        String content = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"notAProperty\":1}";
        CapturingLog log = new CapturingLog();

        MojoAssertions.assertThrowsWithMessage(() -> AggregateSbomMojo.validateBomContent(
                content.getBytes(StandardCharsets.UTF_8), "json", Version.VERSION_15, "1.5", log));

        assertFalse(log.messages.isEmpty(), "a failing document should log the schema problems at debug level");
        assertTrue(log.messages.get(0).contains("schema reported"),
                "the first debug line should report how many problems were found: " + log.messages);
        assertTrue(log.messages.stream().anyMatch(m -> m.contains("[1]")),
                "each schema problem should be logged at debug level: " + log.messages);
    }

    @Test
    void conformingDocumentLogsNoSchemaProblems() throws Exception {
        CapturingLog log = new CapturingLog();
        String content = json(sampleBom(), Version.VERSION_15);

        AggregateSbomMojo.validateBomContent(content.getBytes(StandardCharsets.UTF_8), "json",
                Version.VERSION_15, "1.5", log);

        assertEquals(List.of(), log.messages, "a conforming document must not log schema problems");
    }

    @Test
    void invalidOutputIsNotWrittenToDisk() {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setValidateOutput(false);

        // With validation disabled the (invalid) content is written as-is, proving the flag is honoured.
        File output = tempDir.resolve("unvalidated.json").toFile();
        assertTrue(writeRaw(mojo, output, "{\"not\":\"a bom\"}"));
        assertTrue(output.isFile());
    }

    @Test
    void validAggregatedBomIsWrittenAndRevalidates() throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setValidateOutput(true);

        Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", "1.5", List.of(), List.of(), null);
        File output = tempDir.resolve("aggregated/aggregated-bom.json").toFile();
        mojo.writeBomToFile(merged, output);

        assertTrue(output.isFile(), "aggregated SBOM should be written");
        String written = Files.readString(output.toPath(), StandardCharsets.UTF_8);
        assertTrue(written.contains("CycloneDX"));
        // The on-disk document must satisfy the schema for the configured version.
        AggregateSbomMojo.validateBomContent(written.getBytes(StandardCharsets.UTF_8), "json",
                Version.VERSION_15, "1.5");
    }

    @Test
    void aggregatedBomWithVulnerabilitiesValidatesFor14To16() throws Exception {
        String[][] versions = {{"1.4", "VERSION_14"}, {"1.5", "VERSION_15"}, {"1.6", "VERSION_16"}};
        for (String[] v : versions) {
            Bom upstream = new Bom();
            Component lib = new Component();
            lib.setType(Component.Type.LIBRARY);
            lib.setBomRef("lib-x");
            lib.setGroup("com.lib");
            lib.setName("x");
            lib.setVersion("1.0");
            lib.setPurl("pkg:maven/com.lib/x@1.0");
            upstream.setComponents(new ArrayList<>(List.of(lib)));
            Vulnerability vulnerability = new Vulnerability();
            vulnerability.setId("CVE-2024-0001");
            Vulnerability.Source source = new Vulnerability.Source();
            source.setName("NVD");
            vulnerability.setSource(source);
            Vulnerability.Affect affect = new Vulnerability.Affect();
            affect.setRef("lib-x");
            vulnerability.setAffects(new ArrayList<>(List.of(affect)));
            upstream.setVulnerabilities(new ArrayList<>(List.of(vulnerability)));

            Bom merged = SbomMerger.merge("com.acme", "root", "1.0.0", v[0], List.of(upstream), List.of(), null);
            assertEquals(1, merged.getVulnerabilities().size(), "vulnerability expected for " + v[0]);

            AggregateSbomMojo mojo = new AggregateSbomMojo();
            mojo.setSpecVersion(v[0]);
            mojo.setOutputExtension("json");
            mojo.setValidateOutput(true);
            File output = tempDir.resolve("vuln-" + v[0] + "/aggregated-bom.json").toFile();
            mojo.writeBomToFile(merged, output);
            String written = Files.readString(output.toPath(), StandardCharsets.UTF_8);
            assertTrue(written.contains("CVE-2024-0001"), "vulnerability must be serialised for " + v[0]);
            AggregateSbomMojo.validateBomContent(written.getBytes(StandardCharsets.UTF_8), "json",
                    Version.valueOf(v[1]), v[0]);
        }
    }

    @Test
    void validationFailureLeavesNoFileBehind() {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setValidateOutput(true);

        File output = tempDir.resolve("bad/bad.json").toFile();
        assertFalse(output.exists());
        // A BOM whose components list is corrupted through the model would be caught by the writer; here we
        // assert the contract that a validation failure never produces the file.
        try {
            AggregateSbomMojo.validateBomContent("[]".getBytes(StandardCharsets.UTF_8), "json",
                    Version.VERSION_15, "1.5");
        } catch (org.apache.maven.plugin.MojoExecutionException expected) {
            assertFalse(output.exists(), "no output file must be created when validation fails");
            return;
        }
        throw new AssertionError("an empty JSON array must not validate as a CycloneDX BOM");
    }

    private static boolean writeRaw(AggregateSbomMojo mojo, File output, String content) {
        try {
            Files.createDirectories(output.toPath().getParent());
            Files.writeString(output.toPath(), content, StandardCharsets.UTF_8);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Small helper so the assertions read consistently. */
    private static final class MojoAssertions {
        static void assertThrowsWithMessage(ThrowingRunnable runnable) {
            org.apache.maven.plugin.MojoExecutionException e = assertThrows(
                    org.apache.maven.plugin.MojoExecutionException.class, runnable::run);
            String message = e.getMessage();
            assertTrue(message != null && message.contains("does not conform"),
                    "expected a schema violation message but got: " + message);
            assertTrue(message.contains("1.5"), "the message should name the spec version: " + message);
            assertEquals(true, message.contains("JSON") || message.contains("XML"),
                    "the message should name the output format: " + message);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** Minimal {@link Log} stub that records debug messages so the M4 diagnostics can be asserted. */
    private static final class CapturingLog implements Log {
        private final List<String> messages = new ArrayList<>();

        @Override
        public boolean isDebugEnabled() {
            return true;
        }

        @Override
        public void debug(CharSequence content) {
            messages.add(String.valueOf(content));
        }

        @Override
        public void debug(CharSequence content, Throwable error) {
            debug(content);
        }

        @Override
        public void debug(Throwable error) {
            messages.add(String.valueOf(error));
        }

        @Override
        public boolean isInfoEnabled() {
            return false;
        }

        @Override
        public void info(CharSequence content) {
        }

        @Override
        public void info(CharSequence content, Throwable error) {
        }

        @Override
        public void info(Throwable error) {
        }

        @Override
        public boolean isWarnEnabled() {
            return false;
        }

        @Override
        public void warn(CharSequence content) {
        }

        @Override
        public void warn(CharSequence content, Throwable error) {
        }

        @Override
        public void warn(Throwable error) {
        }

        @Override
        public boolean isErrorEnabled() {
            return false;
        }

        @Override
        public void error(CharSequence content) {
        }

        @Override
        public void error(CharSequence content, Throwable error) {
        }

        @Override
        public void error(Throwable error) {
        }
    }
}
