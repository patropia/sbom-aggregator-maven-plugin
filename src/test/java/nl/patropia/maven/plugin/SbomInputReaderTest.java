package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomInputReaderTest {

    static final String JSON_BOM = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[]}";
    static final String XML_BOM = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\" version=\"1\"><components/></bom>";

    private static Path write(Path dir, String name, String content) throws Exception {
        Path p = dir.resolve(name);
        Files.write(p, content.getBytes(StandardCharsets.UTF_8));
        return p;
    }

    @Test
    void jsonContentInXmlFileIsParsed(@TempDir Path dir) throws Exception {
        Bom bom = new SbomInputReader(0).read(write(dir, "bom.xml", JSON_BOM).toFile());
        assertNotNull(bom);
    }

    @Test
    void xmlContentInJsonFileIsParsed(@TempDir Path dir) throws Exception {
        Bom bom = new SbomInputReader(0).read(write(dir, "bom.json", XML_BOM).toFile());
        assertNotNull(bom);
    }

    @Test
    void sizeGuardBoundary(@TempDir Path dir) throws Exception {
        int len = JSON_BOM.getBytes(StandardCharsets.UTF_8).length;
        Path file = write(dir, "bom.json", JSON_BOM);
        assertDoesNotThrow(() -> new SbomInputReader(len).read(file.toFile()));
        SbomInputReader.InvalidSbomException e = assertThrows(SbomInputReader.InvalidSbomException.class,
                () -> new SbomInputReader(len - 1).read(file.toFile()));
        assertTrue(e.getMessage().contains("maxSbomSize"), e.getMessage());
    }

    @Test
    void zeroMeansUnlimited(@TempDir Path dir) throws Exception {
        assertNotNull(new SbomInputReader(0).read(write(dir, "bom.json", JSON_BOM).toFile()));
    }

    @Test
    void nonCycloneDxIsRejected(@TempDir Path dir) throws Exception {
        assertThrows(SbomInputReader.InvalidSbomException.class,
                () -> new SbomInputReader(0).read(write(dir, "a.json", "{\"foo\":1}").toFile()));
        assertThrows(SbomInputReader.InvalidSbomException.class,
                () -> new SbomInputReader(0).read(write(dir, "b.json", "just some plain text").toFile()));
    }

    @Test
    void errorMessageDoesNotLeakContent(@TempDir Path dir) throws Exception {
        String bad = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[SECRET-TOKEN-123";
        SbomInputReader.InvalidSbomException e = assertThrows(SbomInputReader.InvalidSbomException.class,
                () -> new SbomInputReader(0).read(write(dir, "bad.json", bad).toFile()));
        StringBuilder all = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            all.append(t.getMessage()).append('\n');
        }
        assertFalse(all.toString().contains("SECRET-TOKEN-123"), all.toString());
    }
}
