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

import java.time.Instant;
import java.util.Locale;

/**
 * Validates and maps the user supplied CycloneDX settings.
 */
public final class SpecValidation {

    /** Supported CycloneDX specification versions. */
    public static final String SUPPORTED_SPEC_VERSIONS = "1.3, 1.4, 1.5, 1.6, 1.7";

    /** Supported serial number generation modes. */
    public static final String SERIAL_NUMBER_MODES = "deterministic, random, none";

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
     * Verifies that the given serial number mode is supported (case-insensitive). A {@code null} or
     * blank value is treated as the default {@code deterministic}.
     *
     * @param mode value from the plugin configuration
     * @throws MojoExecutionException when the value is not supported
     */
    public static void validateSerialNumberMode(String mode) throws MojoExecutionException {
        if (mode == null || mode.trim().isEmpty()) {
            return;
        }
        String normalized = mode.trim().toLowerCase(Locale.ROOT);
        if (!"deterministic".equals(normalized) && !"random".equals(normalized) && !"none".equals(normalized)) {
            throw new MojoExecutionException("Unsupported serialNumberMode '" + mode
                    + "'. Supported values: " + SERIAL_NUMBER_MODES);
        }
    }

    /**
     * Parses an output timestamp string.
     *
     * Rules:
     * - null, blank or a single character means "now" and returns null to indicate the caller
     *   should use the current time. A single character is Maven's convention for a disabled
     *   value (the reproducible-builds guide suggests ``).
     * - an unresolved Maven expression (still containing {@code ${...}}) also means "now".
     * - a purely numeric string is treated as epoch seconds.
     * - otherwise ISO-8601 format is parsed by Instant.parse.
     *
     * @param s input string
     * @return Instant or null when the caller should use the current time
     * @throws MojoExecutionException when the value is invalid
     */
    public static Instant parseOutputTimestamp(String s) throws MojoExecutionException {
        if (s == null) {
            return null;
        }
        String trimmed = s.trim();
        if (trimmed.isEmpty() || trimmed.length() == 1) {
            return null;
        }
        if (trimmed.startsWith("${") && trimmed.endsWith("}")) {
            // Unresolved Maven expression, e.g. ${project.build.outputTimestamp} was not set.
            return null;
        }
        try {
            if (trimmed.matches("\\d+")) {
                long secs = Long.parseLong(trimmed);
                return Instant.ofEpochSecond(secs);
            }
            return Instant.parse(trimmed);
        } catch (RuntimeException e) {
            throw new MojoExecutionException("Invalid outputTimestamp '" + s
                    + "'. Use an ISO-8601 instant (e.g. 2024-01-01T00:00:00Z) or epoch seconds.", e);
        }
    }

    /**
     * Parses a human-friendly size string into bytes. Accepts an integer or a value suffixed with
     * KB/MB/GB (case-insensitive). 0 disables the size check.
     *
     * @param s size string
     * @return number of bytes
     * @throws MojoExecutionException when the value is missing or invalid
     */
    public static long parseMaxBytes(String s) throws MojoExecutionException {
        if (s == null) {
            throw new MojoExecutionException("maxInputSize is required");
        }
        String trimmed = s.trim().toUpperCase(Locale.ROOT);
        if (trimmed.isEmpty()) {
            throw new MojoExecutionException("maxInputSize must not be empty");
        }
        long multiplier = 1L;
        String number = trimmed;
        if (trimmed.endsWith("GB")) {
            multiplier = 1024L * 1024L * 1024L;
            number = trimmed.substring(0, trimmed.length() - 2).trim();
        } else if (trimmed.endsWith("MB")) {
            multiplier = 1024L * 1024L;
            number = trimmed.substring(0, trimmed.length() - 2).trim();
        } else if (trimmed.endsWith("KB")) {
            multiplier = 1024L;
            number = trimmed.substring(0, trimmed.length() - 2).trim();
        }
        long value;
        try {
            value = Long.parseLong(number);
        } catch (NumberFormatException e) {
            throw new MojoExecutionException("Invalid maxInputSize '" + s
                    + "'. Use a non-negative integer optionally suffixed by KB/MB/GB.", e);
        }
        if (value < 0) {
            throw new MojoExecutionException("Invalid maxInputSize '" + s
                    + "'. The value must not be negative (use 0 to disable the size check).");
        }
        try {
            return Math.multiplyExact(value, multiplier);
        } catch (ArithmeticException e) {
            throw new MojoExecutionException("Invalid maxInputSize '" + s
                    + "'. The value is too large (overflow).", e);
        }
    }
}

