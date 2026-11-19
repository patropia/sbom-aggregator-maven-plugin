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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Guards the project hygiene that is required for a public, publishable Maven plugin.
 * <p>
 * These checks are easy to regress in a normal code change (a dependency swapped back to an obsolete coordinate, a
 * scope silently dropped, a workflow removed) but they only surface on Maven Central or in CI, so they are pinned
 * here. Everything is verified against the files in the project directory; no network access is involved.
 * </p>
 */
class ReleaseHygieneTest {

    /** Maven API artifacts that must never be bundled with the plugin: they come from the running Maven. */
    private static final Map<String, String> MAVEN_API_DEPENDENCIES = Map.of(
            "maven-plugin-api", "org.apache.maven",
            "maven-plugin-annotations", "org.apache.maven.plugin-tools",
            "maven-core", "org.apache.maven",
            "maven-resolver-api", "org.apache.maven.resolver");

    /** Coordinates that were removed in favour of maintained ones; they must not come back. */
    private static final Set<String> OBSOLETE_DEPENDENCIES = Set.of(
            "org.eclipse.aether:aether-api",
            "org.eclipse.aether:aether-util",
            "org.apache.maven:maven-artifact-manager");

    private static Path projectDir;
    private static Document pom;

    @BeforeAll
    static void parsePom() throws Exception {
        projectDir = Path.of(System.getProperty("basedir", ".")).toAbsolutePath().normalize();
        Path pomFile = projectDir.resolve("pom.xml");
        assertTrue(Files.isRegularFile(pomFile), "pom.xml not found at " + pomFile);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        pom = builder.parse(pomFile.toFile());
    }

    @Test
    void mavenApisAreProvidedScopedAndNeverBundled() {
        Map<String, String> scopes = dependencyScopes();

        List<String> problems = new ArrayList<>();
        MAVEN_API_DEPENDENCIES.forEach((artifactId, groupId) -> {
            String key = groupId + ":" + artifactId;
            if (!scopes.containsKey(key)) {
                problems.add("Missing dependency " + key);
            } else if (!"provided".equals(scopes.get(key))) {
                problems.add(key + " must have scope 'provided' but has '" + scopes.get(key) + "'");
            }
        });
        assertTrue(problems.isEmpty(), "Maven API dependencies must be provided scoped: " + problems);
    }

    @Test
    void obsoleteAetherCoordinatesAreNotUsed() {
        List<String> offending = dependencyScopes().keySet().stream()
                .filter(OBSOLETE_DEPENDENCIES::contains)
                .toList();
        assertTrue(offending.isEmpty(),
                "Obsolete dependencies found: " + offending
                        + " (use org.apache.maven.resolver:maven-resolver-api instead of aether-api)");
    }

    @Test
    void mavenResolverApiVersionIsMaintainedAndParameterised() {
        Element dependency = findDependency("org.apache.maven.resolver", "maven-resolver-api");
        String version = childText(dependency, "version");
        assertFalse("1.1.0".equals(version),
                "maven-resolver-api must not be pinned to the obsolete 1.1.0 line");
        assertTrue(version == null || version.startsWith("${") || version.compareTo("1.9.0") >= 0,
                "maven-resolver-api should track the Maven 3.9.x resolver line (>= 1.9.0) but was " + version);
    }

    @Test
    void scmUrlsUseSecureProtocols() {
        Element scm = (Element) pom.getElementsByTagName("scm").item(0);
        if (scm == null) {
            fail("pom.xml has no <scm> section; Maven Central requires one");
        }
        String connection = childText(scm, "connection");
        String developerConnection = childText(scm, "developerConnection");
        String url = childText(scm, "url");

        assertAll(
                () -> assertTrue(connection != null && connection.startsWith("scm:git:https://"),
                        "scm connection must use https, was: " + connection),
                () -> assertFalse(connection != null && connection.contains("git://"),
                        "scm connection must not use the unencrypted git:// protocol: " + connection),
                () -> assertTrue(developerConnection != null && developerConnection.startsWith("scm:git:ssh://"),
                        "scm developerConnection must use ssh, was: " + developerConnection),
                () -> assertFalse(developerConnection != null && developerConnection.contains("ssh://github.com:"),
                        "scm developerConnection must be ssh://git@github.com/..., was: " + developerConnection),
                () -> assertTrue(url != null && url.startsWith("https://"),
                        "scm url must use https, was: " + url));
    }

    @Test
    void pomDeclaresProjectMetadataRequiredByCentral() {
        List<String> missing = new ArrayList<>();
        for (String element : List.of("name", "description", "url", "licenses", "developers", "scm", "issueManagement")) {
            if (pom.getElementsByTagName(element).getLength() == 0) {
                missing.add(element);
            }
        }
        assertTrue(missing.isEmpty(), "pom.xml is missing required publishing metadata: " + missing);
    }

    @Test
    void repositoryDoesNotShipEnvironmentOrToolInstallerScripts() {
        for (String candidate : List.of(".install_tools.sh", ".env_setup.sh", "install_tools.sh")) {
            assertFalse(Files.exists(projectDir.resolve(candidate)),
                    candidate + " is a sandbox helper and must not be committed to the repository");
        }
    }

    @Test
    void ciWorkflowRunsTheBuildOnJava17And21() throws IOException {
        String ci = read(".github/workflows/ci.yml");
        assertAll(
                () -> assertTrue(ci.contains("java: [ '17', '21' ]"),
                        "ci.yml must build on Java 17 and 21: " + firstLines(ci)),
                () -> assertTrue(ci.contains("-Prun-its"),
                        "ci.yml must run the integration tests (mvn clean verify -Prun-its)"),
                () -> assertTrue(ci.contains("actions/setup-java"),
                        "ci.yml must set up a JDK"),
                () -> assertTrue(ci.contains("actions/upload-artifact"),
                        "ci.yml should publish test/coverage artifacts"));
    }

    @Test
    void codeqlAndDependabotAreConfigured() throws IOException {
        String codeql = read(".github/workflows/codeql.yml");
        assertAll(
                () -> assertTrue(codeql.contains("github/codeql-action/init"),
                        "codeql.yml must initialise the CodeQL action"),
                () -> assertTrue(codeql.contains("github/codeql-action/analyze"),
                        "codeql.yml must run the CodeQL analysis"),
                () -> assertTrue(codeql.contains("java-kotlin"),
                        "codeql.yml must analyse the Java sources"),
                () -> assertTrue(codeql.contains("security-events: write"),
                        "codeql.yml needs security-events: write to upload results"));

        String dependabot = read(".github/dependabot.yml");
        assertAll(
                () -> assertTrue(dependabot.startsWith("version: 2"),
                        "dependabot.yml must start with 'version: 2'"),
                () -> assertTrue(dependabot.contains("package-ecosystem: 'maven'"),
                        "dependabot.yml must track Maven dependencies"),
                () -> assertTrue(dependabot.contains("package-ecosystem: 'github-actions'"),
                        "dependabot.yml must track GitHub Actions"));
    }

    @Test
    void releaseWorkflowUsesSupportedActions() throws IOException {
        String release = read(".github/workflows/release.yml");
        assertAll(
                () -> assertFalse(release.contains("action-gh-release@v1"),
                        "release.yml must not use softprops/action-gh-release@v1 (too old for current runners)"),
                () -> assertFalse(release.matches("(?s).*actions/checkout@v[123].*"),
                        "release.yml must not pin actions/checkout to major versions 1/2/3; use checkout@v4+"),
                () -> assertFalse(release.matches("(?s).*actions/setup-java@v[123].*"),
                        "release.yml must not pin actions/setup-java to major versions 1/2/3; use setup-java@v4+"),
                () -> assertFalse(release.contains("${{ env.VERSION }}"),
                        "release.yml must not reference ${{ env.VERSION }} unless it is defined at job/workflow scope")
        );
    }

    @Test
    void communityHealthFilesArePresent() throws IOException {
        for (String file : List.of("SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "LICENSE", "CHANGELOG.md")) {
            Path path = projectDir.resolve(file);
            assertTrue(Files.isRegularFile(path), file + " is missing from the project root");
            assertFalse(Files.readString(path, StandardCharsets.UTF_8).isBlank(), file + " is empty");
        }
        assertTrue(read("SECURITY.md").contains("security/advisories/new"),
                "SECURITY.md must explain how to report a vulnerability privately");
    }

    // ------------------------------------------------------------------ helpers

    private static String read(String relativePath) throws IOException {
        Path path = projectDir.resolve(relativePath);
        assertTrue(Files.isRegularFile(path), relativePath + " is missing from the project");
        return Files.readString(path, StandardCharsets.UTF_8).replace("\r\n", "\n");
    }

    private static String firstLines(String text) {
        String[] lines = text.split("\n");
        return String.join(" | ", List.of(lines).subList(0, Math.min(5, lines.length)));
    }

    /** Maps {@code groupId:artifactId} to the dependency scope, defaulting to {@code compile} as Maven does. */
    private static Map<String, String> dependencyScopes() {
        Map<String, String> scopes = new LinkedHashMap<>();
        NodeList dependencies = pom.getElementsByTagName("dependency");
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dependency = (Element) dependencies.item(i);
            String groupId = childText(dependency, "groupId");
            String artifactId = childText(dependency, "artifactId");
            if (groupId == null || artifactId == null) {
                continue;
            }
            String scope = childText(dependency, "scope");
            scopes.put(groupId + ":" + artifactId, scope == null ? "compile" : scope);
        }
        return scopes;
    }

    private static Element findDependency(String groupId, String artifactId) {
        NodeList dependencies = pom.getElementsByTagName("dependency");
        for (int i = 0; i < dependencies.getLength(); i++) {
            Element dependency = (Element) dependencies.item(i);
            if (groupId.equals(childText(dependency, "groupId"))
                    && artifactId.equals(childText(dependency, "artifactId"))) {
                return dependency;
            }
        }
        throw new AssertionError("pom.xml does not declare " + groupId + ":" + artifactId);
    }

    private static String childText(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE && name.equals(child.getNodeName())) {
                return child.getTextContent().trim();
            }
        }
        return null;
    }

    @Test
    void dependencyScopesAreSane() {
        // Guards the helper itself: a dependency without an explicit scope is compile scoped in Maven terms.
        assertEquals("test", dependencyScopes().get("org.junit.jupiter:junit-jupiter"));
        assertEquals("provided", dependencyScopes().get("org.apache.maven:maven-core"));
    }
}
