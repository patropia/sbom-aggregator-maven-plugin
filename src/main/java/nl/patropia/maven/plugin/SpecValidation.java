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

    /**
     * Parse a human friendly size string into a number of bytes.
     * Accepts a plain decimal number (bytes) or with a suffix: KB, MB, GB (case-insensitive).
     * 0 means no limit.
     *
     * @param size the user supplied string
     * @return the number of bytes
     * @throws MojoExecutionException when the value is malformed or negative
     */
    public static long parseMaxBytes(String size) throws MojoExecutionException {
        if (size == null) {
            throw new MojoExecutionException("maxInputSize is required");
        }
        String s = size.trim();
        if (s.isEmpty()) {
            throw new MojoExecutionException("maxInputSize must not be empty");
        }
        String unit = "";
        int i = s.length() - 1;
        while (i >= 0 && !Character.isDigit(s.charAt(i))) i--;
        if (i < s.length() - 1) {
            unit = s.substring(i + 1).trim().toUpperCase(Locale.ROOT);
            s = s.substring(0, i + 1).trim();
        }
        long value;
        try {
            value = Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw new MojoExecutionException("Invalid maxInputSize value '" + size + "'");
        }
        if (value < 0) throw new MojoExecutionException("maxInputSize must not be negative: '" + size + "'");
        switch (unit) {
            case "":
                return value;
            case "KB":
                try { return Math.multiplyExact(value, 1024L); } catch (ArithmeticException ae) {
                    throw new MojoExecutionException("maxInputSize too large: '" + size + "'");
                }
            case "MB":
                try { return Math.multiplyExact(value, 1024L * 1024L); } catch (ArithmeticException ae) {
                    throw new MojoExecutionException("maxInputSize too large: '" + size + "'");
                }
            case "GB":
                try { return Math.multiplyExact(value, 1024L * 1024L * 1024L); } catch (ArithmeticException ae) {
                    throw new MojoExecutionException("maxInputSize too large: '" + size + "'");
                }
            default:
                throw new MojoExecutionException("Unknown size unit in maxInputSize: '" + size + "' (supported: KB, MB, GB)");
        }
    }
}
