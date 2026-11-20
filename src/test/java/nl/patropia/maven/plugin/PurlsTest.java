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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link Purls}: Maven purl layout, qualifier handling and percent-encoding.
 */
class PurlsTest {

    @Test
    void buildsPlainMavenPurl() {
        assertEquals("pkg:maven/com.acme/lib@1.0.0", Purls.maven("com.acme", "lib", "1.0.0", null, null));
    }

    @Test
    void omitsJarNullAndBlankType() {
        assertEquals("pkg:maven/g/a@1", Purls.maven("g", "a", "1", "jar", null));
        assertEquals("pkg:maven/g/a@1", Purls.maven("g", "a", "1", "JAR", null));
        assertEquals("pkg:maven/g/a@1", Purls.maven("g", "a", "1", " jar ", null));
        assertEquals("pkg:maven/g/a@1", Purls.maven("g", "a", "1", "  ", " "));
    }

    @Test
    void addsNonJarTypeQualifier() {
        assertEquals("pkg:maven/g/a@1?type=pom", Purls.maven("g", "a", "1", "pom", null));
    }

    @Test
    void sortsQualifiersAlphabetically() {
        assertEquals("pkg:maven/g/a@1?classifier=sources&type=zip",
                Purls.maven("g", "a", "1", "zip", "sources"));
        assertEquals("pkg:maven/g/a@1?classifier=cyclonedx",
                Purls.maven("g", "a", "1", "jar", "cyclonedx"));
    }

    @Test
    void encodesSpecialCharactersInSegmentsAndQualifiers() {
        assertEquals("pkg:maven/com.acme/lib@1.0%2Bbuild%40x",
                Purls.maven("com.acme", "lib", "1.0+build@x", null, null));
        assertEquals("pkg:maven/g/a@1?classifier=a%20b", Purls.maven("g", "a", "1", null, "a b"));
    }

    @Test
    void rejectsBlankCoordinates() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> Purls.maven(" ", "a", "1", null, null));
        assertEquals("groupId, artifactId and version are required for a Maven purl", error.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Purls.maven("g", null, "1", null, null));
        assertThrows(IllegalArgumentException.class, () -> Purls.maven("g", "a", "", null, null));
    }

    @Test
    void encodeKeepsUnreservedCharacters() {
        String unreserved = "ABCxyz019-._~";
        assertEquals(unreserved, Purls.encode(unreserved));
    }

    @Test
    void encodeEscapesReservedAndMultiByteCharactersAsUppercaseHex() {
        assertEquals("%2B%40%20%2F%3A%3F", Purls.encode("+@ /:?"));
        assertEquals("caf%C3%A9", Purls.encode("café"));
    }

    @Test
    void encodeOfNullOrEmptyIsEmpty() {
        assertEquals("", Purls.encode(null));
        assertEquals("", Purls.encode(""));
    }
}
