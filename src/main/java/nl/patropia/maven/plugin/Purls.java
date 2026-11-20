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

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * Builds <a href="https://github.com/package-url/purl-spec">package URLs</a> for Maven artifacts.
 * <p>
 * The plugin only needs Maven purls, so this class is a small, dependency-free implementation of the part of the
 * specification that matters here: percent-encoded path segments and alphabetically sorted qualifiers. Component
 * identifiers end up in {@code bom-ref} values and in dependency graphs, so they must never contain characters such
 * as a space, {@code +} or {@code @} verbatim.
 * </p>
 */
final class Purls {

    /** Default Maven artifact type; the purl specification omits it when it has this value. */
    private static final String TYPE_JAR = "jar";

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private Purls() {
        // utility class
    }

    /**
     * Builds {@code pkg:maven/groupId/artifactId@version} with optional {@code classifier} and {@code type}
     * qualifiers.
     *
     * @param groupId    Maven groupId, must not be blank
     * @param artifactId Maven artifactId, must not be blank
     * @param version    Maven version, must not be blank
     * @param type       artifact type; {@code null}, blank or {@code jar} are omitted
     * @param classifier artifact classifier; {@code null} or blank are omitted
     * @return the purl
     * @throws IllegalArgumentException when groupId, artifactId or version is blank
     */
    static String maven(String groupId, String artifactId, String version, String type, String classifier) {
        if (isBlank(groupId) || isBlank(artifactId) || isBlank(version)) {
            throw new IllegalArgumentException("groupId, artifactId and version are required for a Maven purl");
        }
        StringBuilder purl = new StringBuilder("pkg:maven/")
                .append(encode(groupId))
                .append('/')
                .append(encode(artifactId))
                .append('@')
                .append(encode(version));

        Map<String, String> qualifiers = new TreeMap<>();
        if (!isBlank(classifier)) {
            qualifiers.put("classifier", encode(classifier));
        }
        if (!isBlank(type) && !TYPE_JAR.equalsIgnoreCase(type.trim())) {
            qualifiers.put("type", encode(type));
        }
        if (!qualifiers.isEmpty()) {
            purl.append('?');
            boolean first = true;
            for (Map.Entry<String, String> qualifier : qualifiers.entrySet()) {
                if (!first) {
                    purl.append('&');
                }
                purl.append(qualifier.getKey()).append('=').append(qualifier.getValue());
                first = false;
            }
        }
        return purl.toString();
    }

    /**
     * Percent-encodes a purl path segment or qualifier value as UTF-8. Unreserved characters
     * ({@code A-Z a-z 0-9 - . _ ~}) are kept, everything else becomes an uppercase {@code %XX} escape.
     *
     * @param value the raw value; {@code null} is treated as an empty string
     * @return the encoded value
     */
    static String encode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int c = b & 0xFF;
            if (isUnreserved(c)) {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(HEX[c >> 4]).append(HEX[c & 0x0F]);
            }
        }
        return encoded.toString();
    }

    private static boolean isUnreserved(int c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~';
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
