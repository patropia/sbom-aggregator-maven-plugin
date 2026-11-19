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

import org.apache.maven.plugin.MojoExecutionException;
import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SpecValidation} and for the UTF-8 safe serialisation performed by
 * {@link AggregateSbomMojo#writeBomToFile(Bom, java.io.File)}.
 */
class SpecValidationTest {

    private static final String UNICODE_NAME = "\u00dcn\u00efc\u00f8d\u00e9-lib";

    // ------------------------------------------------------------ specVersion

    @ParameterizedTest
    @ValueSource(strings = {"1.3", "1.4", "1.5", "1.6", "1.7", " 1.5 ", "\t1.6\n"})
    void acceptsSupportedSpecVersions(String specVersion) throws Exception {
        SpecValidation.validateSpecVersion(specVersion);
        assertNotNull(SpecValidation.toCycloneDxVersion(specVersion));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "1.0", "1.2", "1.8", "2.0", "latest", "v1.5"})
    void rejectsUnsupportedSpecVersions(String specVersion) {
        MojoExecutionException error =
                assertThrows(MojoExecutionException.class, () -> SpecValidation.validateSpecVersion(specVersion));
        assertTrue(error.getMessage().contains("specVersion"), "message should name the setting: " + error.getMessage());
    }

    @Test
    void rejectsNullSpecVersionWithAClearMessage() {
        MojoExecutionException error =
                assertThrows(MojoExecutionException.class, () -> SpecValidation.validateSpecVersion(null));
        assertTrue(error.getMessage().contains(SpecValidation.SUPPORTED_SPEC_VERSIONS),
                "message should list the supported versions: " + error.getMessage());
    }

    @Test
    void mapsSpecVersionsToCycloneDxVersions() throws Exception {
        assertEquals(Version.VERSION_13, SpecValidation.toCycloneDxVersion("1.3"));
        assertEquals(Version.VERSION_14, SpecValidation.toCycloneDxVersion("1.4"));
        assertEquals(Version.VERSION_15, SpecValidation.toCycloneDxVersion("1.5"));
        assertEquals(Version.VERSION_16, SpecValidation.toCycloneDxVersion("1.6"));
        assertEquals(Version.VERSION_17, SpecValidation.toCycloneDxVersion("1.7"));
        assertEquals(Version.VERSION_15, SpecValidation.toCycloneDxVersion(" 1.5 "));
    }

    @Test
    void toCycloneDxVersionThrowsInsteadOfFallingBack() {
        assertThrows(MojoExecutionException.class, () -> SpecValidation.toCycloneDxVersion("1.2"));
        assertThrows(MojoExecutionException.class, () -> SpecValidation.toCycloneDxVersion("nonsense"));
        assertThrows(MojoExecutionException.class, () -> SpecValidation.toCycloneDxVersion(""));
        assertThrows(MojoExecutionException.class, () -> SpecValidation.toCycloneDxVersion(null));
    }

    // ------------------------------------------------------- outputExtension

    @ParameterizedTest
    @ValueSource(strings = {"json", "JSON", "Xml", " xml ", "\tJson\n"})
    void acceptsSupportedOutputExtensions(String extension) throws Exception {
        SpecValidation.validateOutputExtension(extension);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "yaml", "txt", "json5", "JSONX"})
    void rejectsUnsupportedOutputExtensions(String extension) {
        MojoExecutionException error = assertThrows(MojoExecutionException.class,
                () -> SpecValidation.validateOutputExtension(extension));
        assertTrue(error.getMessage().contains("outputExtension"),
                "message should name the setting: " + error.getMessage());
    }

    @Test
    void rejectsNullOutputExtension() {
        assertThrows(MojoExecutionException.class, () -> SpecValidation.validateOutputExtension(null));
    }

    // --------------------------------------------------------------- writers

    @Test
    void writeBomToFileWritesJsonAsUtf8(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");

        Path output = tempDir.resolve("aggregated-bom.json");
        mojo.writeBomToFile(bomWithUnicodeComponent(), output.toFile());

        assertTrue(Files.exists(output), "output file must be written");
        String content = Files.readString(output, StandardCharsets.UTF_8);
        assertTrue(content.contains(UNICODE_NAME),
                "the UTF-8 component name must be written verbatim: " + content);

        Bom parsed = new JsonParser().parse(output.toFile());
        assertEquals(UNICODE_NAME, parsed.getComponents().get(0).getName(),
                "JSON round-trip must preserve the component name");
        assertEquals("com.acme", parsed.getComponents().get(0).getGroup());
        assertEquals("root", parsed.getMetadata().getComponent().getName());
    }

    @Test
    void writeBomToFileWritesXmlAsUtf8(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("XML");

        Path output = tempDir.resolve("aggregated-bom.xml");
        mojo.writeBomToFile(bomWithUnicodeComponent(), output.toFile());

        String content = Files.readString(output, StandardCharsets.UTF_8);
        assertTrue(content.contains(UNICODE_NAME),
                "the UTF-8 component name must be written verbatim: " + content);

        Bom parsed = new XmlParser().parse(output.toFile());
        assertEquals(UNICODE_NAME, parsed.getComponents().get(0).getName(),
                "XML round-trip must preserve the component name");
        assertEquals("root", parsed.getMetadata().getComponent().getName());
    }

    @Test
    void writeBomToFileCreatesMissingParentDirectories(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.6");
        mojo.setOutputExtension("json");

        Path output = tempDir.resolve("nested/dir/aggregated-bom.json");
        mojo.writeBomToFile(bomWithUnicodeComponent(), output.toFile());
        assertTrue(Files.exists(output));
    }

    @Test
    void writeBomToFileFailsForUnsupportedSpecVersion(@TempDir Path tempDir) {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.2");
        mojo.setOutputExtension("json");

        Path output = tempDir.resolve("aggregated-bom.json");
        assertThrows(MojoExecutionException.class,
                () -> mojo.writeBomToFile(bomWithUnicodeComponent(), output.toFile()));
    }

    private static Bom bomWithUnicodeComponent() {
        Bom bom = new Bom();
        bom.setVersion(1);

        Metadata metadata = new Metadata();
        Component root = new Component();
        root.setType(Component.Type.APPLICATION);
        root.setGroup("com.acme");
        root.setName("root");
        root.setVersion("1.0.0");
        root.setPurl("pkg:maven/com.acme/root@1.0.0");
        root.setBomRef(root.getPurl());
        metadata.setComponent(root);
        bom.setMetadata(metadata);

        Component library = new Component();
        library.setType(Component.Type.LIBRARY);
        library.setGroup("com.acme");
        library.setName(UNICODE_NAME);
        library.setVersion("1.0.0");
        library.setPurl("pkg:maven/com.acme/unicode-lib@1.0.0");
        library.setBomRef(library.getPurl());

        List<Component> components = new ArrayList<>();
        components.add(library);
        bom.setComponents(components);
        return bom;
    }
}
