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
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DiffSbomMojoTest {

    @TempDir
    Path tmp;

    private static File resource(String name) throws URISyntaxException {
        return new File(DiffSbomMojoTest.class.getResource("diff/" + name).toURI());
    }

    private DiffSbomMojo mojo(File baseline, File current) {
        DiffSbomMojo mojo = new DiffSbomMojo();
        mojo.setBaseline(baseline);
        mojo.setCurrent(current);
        mojo.setOutputDirectory(tmp.resolve("out").toFile());
        return mojo;
    }

    private String read(String name) throws Exception {
        return new String(Files.readAllBytes(tmp.resolve("out").resolve(name)), StandardCharsets.UTF_8);
    }

    @Test
    void writesJsonAndMarkdownReports() throws Exception {
        mojo(resource("baseline.json"), resource("current.json")).execute();

        String json = read(DiffSbomMojo.JSON_REPORT);
        assertTrue(json.contains("\"CVE-2024-0003\""), json);
        assertTrue(json.contains("\"fresh\""), json);
        assertTrue(json.contains("\"upgraded\""), json);
        assertTrue(json.contains("\"downgraded\""), json);
        assertFalse(json.contains("timestamp"), json);

        String md = read(DiffSbomMojo.MARKDOWN_REPORT);
        assertTrue(md.startsWith("# SBOM diff"), md);
        assertTrue(md.contains("CVE-2024-0003"), md);
        assertTrue(md.contains("## Added components"), md);
    }

    @Test
    void jsonReportIsDeterministic() throws Exception {
        DiffSbomMojo first = mojo(resource("baseline.json"), resource("current.json"));
        first.setReportFormats(List.of("json"));
        first.execute();
        String a = read(DiffSbomMojo.JSON_REPORT);
        first.execute();
        assertEquals(a, read(DiffSbomMojo.JSON_REPORT));
        assertFalse(Files.exists(tmp.resolve("out").resolve(DiffSbomMojo.MARKDOWN_REPORT)));
    }

    @Test
    void markdownEscapesUntrustedValues() throws Exception {
        String bom = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":["
                + "{\"type\":\"library\",\"bom-ref\":\"x\",\"name\":\"a|b<script>alert(1)</script>\\n| x\","
                + "\"version\":\"1.0\"}]}";
        File current = tmp.resolve("evil.json").toFile();
        Files.write(current.toPath(), bom.getBytes(StandardCharsets.UTF_8));
        File baseline = tmp.resolve("empty.json").toFile();
        Files.write(baseline.toPath(),
                "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1}".getBytes(StandardCharsets.UTF_8));

        DiffSbomMojo mojo = mojo(baseline, current);
        mojo.setReportFormats(List.of("markdown"));
        mojo.execute();

        String md = read(DiffSbomMojo.MARKDOWN_REPORT);
        assertFalse(md.contains("<script>"), md);
        assertTrue(md.contains("a\\|b&lt;script&gt;"), md);
        String row = md.lines().filter(l -> l.contains("script")).findFirst().orElseThrow();
        // 4 columns -> 5 unescaped pipes
        assertEquals(5, row.replace("\\|", "").chars().filter(c -> c == '|').count(), row);
    }

    @Test
    void escapeHandlesMetacharacters() {
        assertEquals("\\* \\_ \\[x\\] \\` \\\\ &lt;a&gt; &amp;", DiffSbomMojo.escape("* _ [x] ` \\ <a> &"));
        assertEquals("a b", DiffSbomMojo.escape("a\r\nb").replace("  ", " "));
        assertEquals("-", DiffSbomMojo.escape(null));
    }

    @Test
    void failOnNewVulnerabilitiesFailsWithIds() throws Exception {
        DiffSbomMojo mojo = mojo(resource("baseline.json"), resource("current.json"));
        mojo.setFailOnNewVulnerabilities(true);
        MojoFailureException e = assertThrows(MojoFailureException.class, mojo::execute);
        assertTrue(e.getMessage().contains("CVE-2024-0003"), e.getMessage());
        // reports are still written so the failure can be investigated
        assertTrue(Files.exists(tmp.resolve("out").resolve(DiffSbomMojo.JSON_REPORT)));
    }

    @Test
    void failOnNewVulnerabilitiesPassesWithoutNewOnes() throws Exception {
        // swapped: the "current" side only resolves vulnerabilities except the shared one
        DiffSbomMojo mojo = mojo(resource("current.json"), resource("current.json"));
        mojo.setFailOnNewVulnerabilities(true);
        mojo.execute();
        assertTrue(read(DiffSbomMojo.JSON_REPORT).contains("\"newVulnerabilities\" : 0"));
    }

    @Test
    void skipDoesNothing() throws Exception {
        DiffSbomMojo mojo = mojo(null, null);
        mojo.setSkip(true);
        mojo.execute();
        assertFalse(Files.exists(tmp.resolve("out")));
    }

    @Test
    void missingBaselineFails() throws Exception {
        DiffSbomMojo unset = mojo(null, resource("current.json"));
        assertTrue(assertThrows(MojoFailureException.class, unset::execute).getMessage()
                .contains("sbomAggregator.diff.baseline"));

        DiffSbomMojo missing = mojo(tmp.resolve("nope.json").toFile(), resource("current.json"));
        assertTrue(assertThrows(MojoFailureException.class, missing::execute).getMessage()
                .contains("does not exist"));
    }

    @Test
    void currentDefaultsToAggregatedSbomFromOutputNameAndExtension() throws Exception {
        File build = tmp.resolve("target").toFile();
        Files.createDirectories(build.toPath());
        Files.copy(resource("current.json").toPath(), build.toPath().resolve("custom.json"));
        DiffSbomMojo mojo = mojo(resource("baseline.json"), null);
        mojo.setBuildDirectory(build);
        mojo.setOutputName("custom");
        mojo.setOutputExtension("JSON");
        assertEquals(new File(build, "custom.json"), mojo.currentSbom());
        mojo.execute();
        assertTrue(Files.exists(tmp.resolve("out").resolve("sbom-diff.json")));
    }

    @Test
    void missingDefaultCurrentNamesTheExpectedFile() throws Exception {
        DiffSbomMojo mojo = mojo(resource("baseline.json"), null);
        mojo.setBuildDirectory(tmp.resolve("target").toFile());
        mojo.setOutputName("custom");
        mojo.setOutputExtension("xml");
        String message = assertThrows(MojoFailureException.class, mojo::execute).getMessage();
        assertTrue(message.contains("does not exist"), message);
        assertTrue(message.contains("custom.xml"), message);
    }

    @Test
    void currentWithoutBuildDirectoryAsksForConfiguration() throws Exception {
        DiffSbomMojo mojo = mojo(resource("baseline.json"), null);
        assertTrue(assertThrows(MojoFailureException.class, mojo::execute).getMessage()
                .contains("sbomAggregator.diff.current"));
    }

    @Test
    void invalidBaselineFails() throws Exception {
        File bad = tmp.resolve("bad.json").toFile();
        Files.write(bad.toPath(), "not an sbom".getBytes(StandardCharsets.UTF_8));
        DiffSbomMojo mojo = mojo(bad, resource("current.json"));
        assertThrows(MojoFailureException.class, mojo::execute);
    }

    @Test
    void unknownFormatFails() throws Exception {
        DiffSbomMojo mojo = mojo(resource("baseline.json"), resource("current.json"));
        mojo.setReportFormats(Collections.singletonList("json,html"));
        MojoExecutionException e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(e.getMessage().contains("html"), e.getMessage());
    }

    @Test
    void maxSbomSizeIsEnforced() throws Exception {
        DiffSbomMojo mojo = mojo(resource("baseline.json"), resource("current.json"));
        mojo.setMaxSbomSize("10");
        assertThrows(MojoFailureException.class, mojo::execute);
    }
}
