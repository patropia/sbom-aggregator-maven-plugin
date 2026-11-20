package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.BomParserFactory;
import org.cyclonedx.parsers.Parser;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

/**
 * Helper to read and validate an SBOM file with a size guard and content detection.
 */
final class SbomInputReader {
    private final long maxBytes; // 0 means no limit

    SbomInputReader(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    static final class InvalidSbomException extends Exception {
        InvalidSbomException(String message) { super(message); }
        InvalidSbomException(String message, Throwable cause) { super(message, cause); }
    }

    Bom read(File file) throws InvalidSbomException {
        try {
            // read with a size guard: stop once maxBytes + 1 is reached
            try (InputStream in = Files.newInputStream(file.toPath())) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int r;
                long total = 0L;
                while ((r = in.read(buf)) != -1) {
                    total += r;
                    if (maxBytes > 0 && total > maxBytes) {
                        throw new InvalidSbomException(file.getAbsolutePath() + ": " + total
                                + "+ bytes exceeds maxInputSize " + maxBytes);
                    }
                    out.write(buf, 0, r);
                }
                byte[] bytes = out.toByteArray();
                // detect CycloneDX-like content
                boolean looks = BomParserFactory.looksLikeCycloneDX(bytes);
                if (!looks) {
                    throw new InvalidSbomException(file.getAbsolutePath() + ": is not a CycloneDX JSON/XML document");
                }
                // create parser from bytes and parse
                Parser parser = BomParserFactory.createParser(bytes);
                Bom bom = parser.parse(bytes);
                if (bom == null) {
                    throw new InvalidSbomException(file.getAbsolutePath() + ": parser returned null BOM");
                }
                return bom;
            }
        } catch (InvalidSbomException e) {
            throw e;
        } catch (IOException e) {
            throw new InvalidSbomException("I/O error reading " + file.getAbsolutePath() + ": " + e.getClass().getSimpleName(), e);
        } catch (Exception e) {
            // avoid echoing file contents from parser messages; include only the exception class and the first line for known parser exceptions
            if (e instanceof org.cyclonedx.exception.ParseException) {
                String reason = e.getClass().getSimpleName();
                String msg = e.getMessage();
                if (msg != null && !msg.isBlank()) {
                    String firstLine = msg.split("\\R", 2)[0];
                    if (firstLine.length() > 200) firstLine = firstLine.substring(0, 200) + "...";
                    reason = reason + ": " + firstLine;
                }
                throw new InvalidSbomException("Failed to parse SBOM " + file.getAbsolutePath() + ": " + reason, e);
            }
            // For other runtime errors include only the exception class name to avoid leaking content
            throw new InvalidSbomException("Failed to parse SBOM " + file.getAbsolutePath() + ": " + e.getClass().getSimpleName(), e);
        }
    }
}
