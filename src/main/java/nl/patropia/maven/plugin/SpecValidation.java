package nl.patropia.maven.plugin;

import org.apache.maven.plugin.MojoExecutionException;
import org.cyclonedx.Version;

import java.util.Locale;

/**
 * Validates and maps the user supplied CycloneDX settings.
 */
public final class SpecValidation {

    /** Supported CycloneDX specification versions. */
    public static final String SUPPORTED_SPEC_VERSIONS = "1.3, 1.4, 1.5, 1.6, 1.7";

    private SpecValidation() {
        // utility class
    }

    /**
     * Verifies that the given specification version is supported.
     *
     * @param specVersion value from the plugin configuration, e.g. {@code 1.5}
     * @throws MojoExecutionException when the value is missing or not supported
     */
    public static void validateSpecVersion(String specVersion) throws MojoExecutionException {
        if (specVersion == null) {
            throw new MojoExecutionException(
                    "specVersion is required; supported values: " + SUPPORTED_SPEC_VERSIONS);
        }
        String trimmed = specVersion.trim();
        if (trimmed.isEmpty()) {
            throw new MojoExecutionException(
                    "specVersion must not be empty; supported values: " + SUPPORTED_SPEC_VERSIONS);
        }
        switch (trimmed) {
            case "1.3":
            case "1.4":
            case "1.5":
            case "1.6":
            case "1.7":
                return;
            default:
                throw new MojoExecutionException("Unsupported specVersion '" + specVersion
                        + "'. Supported values: " + SUPPORTED_SPEC_VERSIONS);
        }
    }

    /**
     * Verifies that the given output extension is {@code json} or {@code xml} (case-insensitive).
     *
     * @param outputExtension value from the plugin configuration, e.g. {@code json}
     * @throws MojoExecutionException when the value is missing or not supported
     */
    public static void validateOutputExtension(String outputExtension) throws MojoExecutionException {
        if (outputExtension == null) {
            throw new MojoExecutionException(
                    "outputExtension is required; supported values: json, xml");
        }
        String lowerCase = outputExtension.trim().toLowerCase(Locale.ROOT);
        if (!"json".equals(lowerCase) && !"xml".equals(lowerCase)) {
            throw new MojoExecutionException("Unsupported outputExtension '" + outputExtension
                    + "'. Supported values: json, xml");
        }
    }

    /**
     * Maps a specification version to the CycloneDX {@link Version} enum.
     *
     * @param specVersion value from the plugin configuration
     * @return the matching CycloneDX version
     * @throws MojoExecutionException when the value is missing or not supported (there is no
     *                                silent fallback)
     */
    public static Version toCycloneDxVersion(String specVersion) throws MojoExecutionException {
        validateSpecVersion(specVersion);
        switch (specVersion.trim()) {
            case "1.7":
                return Version.VERSION_17;
            case "1.6":
                return Version.VERSION_16;
            case "1.5":
                return Version.VERSION_15;
            case "1.4":
                return Version.VERSION_14;
            case "1.3":
                return Version.VERSION_13;
            default:
                throw new MojoExecutionException("Unsupported specVersion '" + specVersion
                        + "'. Supported values: " + SUPPORTED_SPEC_VERSIONS);
        }
    }
}
