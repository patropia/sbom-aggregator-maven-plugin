package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AggregateSbomMojoTest {

    @Test
    void testParseAndMergeBoms(@TempDir Path tempDir) throws Exception {
        // 1. Create Sample SBOM 1
        File bomFile1 = tempDir.resolve("bom1.json").toFile();
        String json1 = "{\n" +
                "  \"bomFormat\": \"CycloneDX\",\n" +
                "  \"specVersion\": \"1.5\",\n" +
                "  \"version\": 1,\n" +
                "  \"components\": [\n" +
                "    {\n" +
                "      \"type\": \"library\",\n" +
                "      \"name\": \"component-a\",\n" +
                "      \"version\": \"1.0.0\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        try (FileWriter writer = new FileWriter(bomFile1)) {
            writer.write(json1);
        }

        // 2. Create Sample SBOM 2
        File bomFile2 = tempDir.resolve("bom2.json").toFile();
        String json2 = "{\n" +
                "  \"bomFormat\": \"CycloneDX\",\n" +
                "  \"specVersion\": \"1.5\",\n" +
                "  \"version\": 1,\n" +
                "  \"components\": [\n" +
                "    {\n" +
                "      \"type\": \"library\",\n" +
                "      \"name\": \"component-b\",\n" +
                "      \"version\": \"2.0.0\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        try (FileWriter writer = new FileWriter(bomFile2)) {
            writer.write(json2);
        }

        // 3. Parse BOMs using JsonParser
        JsonParser parser = new JsonParser();
        Bom parsed1 = parser.parse(bomFile1);
        Bom parsed2 = parser.parse(bomFile2);

        assertNotNull(parsed1);
        assertNotNull(parsed2);

        // 4. Test Mojo's merge logic
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        Bom merged = mojo.mergeBoms(Arrays.asList(parsed1, parsed2));

        // 5. Assertions
        assertNotNull(merged);
        assertNotNull(merged.getComponents());
        assertEquals(2, merged.getComponents().size(), "Merged BOM should contain components from both files");

        boolean hasComponentA = merged.getComponents().stream().anyMatch(c -> c.getName().equals("component-a"));
        boolean hasComponentB = merged.getComponents().stream().anyMatch(c -> c.getName().equals("component-b"));

        assertTrue(hasComponentA, "Merged BOM should include component-a");
        assertTrue(hasComponentB, "Merged BOM should include component-b");
    }
}