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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
     * Computes a canonical comparison key for a purl so that semantically equal purls written in different ways
     * compare equal. The key is only used for matching; it is never written to the output.
     * <ul>
     *   <li>the scheme and type are lowercased,</li>
     *   <li>namespace segments, name, version, qualifier values and subpath segments are percent-decoded and
     *       re-encoded consistently with {@link #encode(String)},</li>
     *   <li>qualifier keys are lowercased, qualifiers with an empty value are dropped and the rest are sorted by
     *       key,</li>
     *   <li>for type {@code maven} the default qualifier {@code type=jar} is dropped ({@code classifier} and other
     *       qualifiers are kept).</li>
     * </ul>
     *
     * @param purl the purl string
     * @return the canonical key, or {@code null} when the value is blank or not a purl
     */
    static String canonicalKey(String purl) {
        Parsed parsed = parse(purl);
        if (parsed == null) {
            return null;
        }
        StringBuilder key = new StringBuilder("pkg:").append(parsed.type).append('/');
        for (String segment : parsed.namespace) {
            key.append(encode(segment)).append('/');
        }
        key.append(encode(parsed.name));
        if (parsed.version != null) {
            key.append('@').append(encode(parsed.version));
        }
        Map<String, String> qualifiers = new TreeMap<>(parsed.qualifiers);
        if ("maven".equals(parsed.type) && TYPE_JAR.equalsIgnoreCase(qualifiers.getOrDefault("type", ""))) {
            qualifiers.remove("type");
        }
        if (!qualifiers.isEmpty()) {
            char separator = '?';
            for (Map.Entry<String, String> qualifier : qualifiers.entrySet()) {
                key.append(separator).append(qualifier.getKey()).append('=').append(encode(qualifier.getValue()));
                separator = '&';
            }
        }
        if (!parsed.subpath.isEmpty()) {
            key.append('#');
            for (int i = 0; i < parsed.subpath.size(); i++) {
                if (i > 0) {
                    key.append('/');
                }
                key.append(encode(parsed.subpath.get(i)));
            }
        }
        return key.toString();
    }

    /**
     * Returns the canonical key of a reference when it is a purl, otherwise the reference itself.
     *
     * @param reference a purl or any other reference
     * @return the matching key
     */
    static String matchKey(String reference) {
        String key = canonicalKey(reference);
        return key == null ? reference : key;
    }

    /**
     * Returns the decoded namespace of a {@code pkg:maven} purl (the Maven groupId).
     *
     * @param purl the purl string
     * @return the groupId, or {@code null} when the purl is not a Maven purl or has no namespace
     */
    static String mavenGroupId(String purl) {
        Parsed parsed = parse(purl);
        if (parsed == null || !"maven".equals(parsed.type) || parsed.namespace.isEmpty()) {
            return null;
        }
        return String.join("/", parsed.namespace);
    }

    private static Parsed parse(String purl) {
        if (isBlank(purl)) {
            return null;
        }
        String remainder = purl.trim();
        if (remainder.length() < 4 || !remainder.regionMatches(true, 0, "pkg:", 0, 4)) {
            return null;
        }
        remainder = remainder.substring(4);
        while (remainder.startsWith("/")) {
            remainder = remainder.substring(1);
        }
        Parsed parsed = new Parsed();
        int hash = remainder.indexOf('#');
        if (hash >= 0) {
            for (String segment : remainder.substring(hash + 1).split("/")) {
                String decoded = decode(segment);
                if (!decoded.isEmpty() && !".".equals(decoded) && !"..".equals(decoded)) {
                    parsed.subpath.add(decoded);
                }
            }
            remainder = remainder.substring(0, hash);
        }
        int question = remainder.indexOf('?');
        if (question >= 0) {
            for (String pair : remainder.substring(question + 1).split("&")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String value = decode(pair.substring(eq + 1));
                if (!value.isEmpty()) {
                    parsed.qualifiers.put(pair.substring(0, eq).toLowerCase(Locale.ROOT), value);
                }
            }
            remainder = remainder.substring(0, question);
        }
        while (remainder.endsWith("/")) {
            remainder = remainder.substring(0, remainder.length() - 1);
        }
        int at = remainder.lastIndexOf('@');
        if (at >= 0) {
            String version = decode(remainder.substring(at + 1));
            parsed.version = version.isEmpty() ? null : version;
            remainder = remainder.substring(0, at);
        }
        int slash = remainder.indexOf('/');
        if (slash <= 0) {
            return null;
        }
        parsed.type = remainder.substring(0, slash).toLowerCase(Locale.ROOT);
        String[] segments = remainder.substring(slash + 1).split("/");
        for (int i = 0; i < segments.length - 1; i++) {
            String decoded = decode(segments[i]);
            if (!decoded.isEmpty()) {
                parsed.namespace.add(decoded);
            }
        }
        parsed.name = decode(segments[segments.length - 1]);
        if (parsed.name.isEmpty()) {
            return null;
        }
        return parsed;
    }

    /** Lenient UTF-8 percent-decoding; malformed escapes are kept verbatim and {@code +} stays a plus sign. */
    static String decode(String value) {
        if (value == null || value.indexOf('%') < 0) {
            return value == null ? "" : value;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()
                    && Character.digit(value.charAt(i + 1), 16) >= 0
                    && Character.digit(value.charAt(i + 2), 16) >= 0) {
                bytes.write(Character.digit(value.charAt(i + 1), 16) * 16 + Character.digit(value.charAt(i + 2), 16));
                i += 3;
            } else {
                byte[] raw = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                if (Character.isHighSurrogate(c) && i + 1 < value.length()) {
                    raw = value.substring(i, i + 2).getBytes(StandardCharsets.UTF_8);
                    i++;
                }
                bytes.write(raw, 0, raw.length);
                i++;
            }
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }

    /** Parsed purl components (decoded). */
    private static final class Parsed {
        private String type;
        private final List<String> namespace = new ArrayList<>();
        private String name;
        private String version;
        private final Map<String, String> qualifiers = new TreeMap<>();
        private final List<String> subpath = new ArrayList<>();
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
