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
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
                .collect(Collectors.toList());
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
    void ciWorkflowRunsTheBuildOnJava11And17And21() throws IOException {
        String ci = read(".github/workflows/ci.yml");
        assertAll(
                () -> assertTrue(ci.contains("java: [ '11', '17', '21' ]"),
                        "ci.yml must build on Java 11 (the minimum), 17 and 21: " + firstLines(ci)),
                () -> assertTrue(ci.contains("-Prun-its"),
                        "ci.yml must run the integration tests (mvn clean verify -Prun-its)"),
                () -> assertTrue(ci.contains("actions/setup-java"),
                        "ci.yml must set up a JDK"),
                () -> assertTrue(ci.contains("actions/upload-artifact"),
                        "ci.yml should publish test/coverage artifacts"));
    }

    @Test
    void javaBaselineStaysAtJava11() throws IOException {
        String rootPom = read("pom.xml");
        assertAll(
                () -> assertTrue(rootPom.contains("<maven.compiler.release>11</maven.compiler.release>"),
                        "pom.xml must compile with maven.compiler.release 11 (Java 11 is the supported minimum)"),
                () -> assertTrue(rootPom.matches("(?s).*<requireJavaVersion>\\s*<version>\\[11,\\)</version>.*"),
                        "the enforcer requireJavaVersion rule must be [11,)"),
                // A hard-coded source/target in maven-compiler-plugin would shadow maven.compiler.release and could
                // silently raise the bytecode level again.
                () -> assertFalse(rootPom.matches("(?s).*<source>\\s*1[2-9].*"),
                        "pom.xml must not hard-code <source> above 11; maven.compiler.release governs the level"),
                () -> assertFalse(rootPom.matches("(?s).*<target>\\s*1[2-9].*"),
                        "pom.xml must not hard-code <target> above 11; maven.compiler.release governs the level"));

        List<Path> itPoms;
        try (Stream<Path> dirs = Files.list(projectDir.resolve("src/it"))) {
            itPoms = dirs.map(dir -> dir.resolve("pom.xml"))
                    .filter(Files::isRegularFile)
                    .collect(Collectors.toList());
        }
        assertFalse(itPoms.isEmpty(), "expected integration test poms under src/it");
        for (Path itPom : itPoms) {
            String content = Files.readString(itPom, StandardCharsets.UTF_8);
            assertFalse(content.matches("(?s).*<maven\\.compiler\\.[a-z]+>(1[2-9]|[2-9][0-9])</maven\\.compiler.*"),
                    projectDir.relativize(itPom) + " must not raise maven.compiler.* above the Java 11 baseline");
        }
    }

    @Test
    void junitStaysOnTheJava11CompatibleLine() throws IOException {
        // JUnit 6 is built for Java 17, so bumping it back breaks both the build and the test run on Java 11.
        String version = childText(findDependency("org.junit.jupiter", "junit-jupiter"), "version");
        String dependabot = read(".github/dependabot.yml");
        assertAll(
                () -> assertTrue(version != null && version.startsWith("5."),
                        "junit-jupiter must stay on 5.x while Java 11 is supported (JUnit 6 needs Java 17) but was "
                                + version),
                () -> assertTrue(dependabot.contains("'org.junit*:*'"),
                        "dependabot.yml must ignore major JUnit updates, otherwise JUnit 6 is proposed again"));
    }

    @Test
    void javaSourcesKeepToJava11Syntax() throws IOException {
        // CI compiles on JDK 11, but a contributor building on JDK 17/21 would only notice a text block, a record or
        // Stream.toList() when CI fails. Detect the common Java 12+ constructs here, on whatever JDK runs the tests.
        String textBlockStart = "\"" + "\"" + "\"";
        // Stream.toList() needs Java 16; Collectors.toList() is the Java 11 form and must stay allowed.
        java.util.regex.Pattern streamToList =
                java.util.regex.Pattern.compile("(?<!Collectors)\\." + "toList\\\(\\s*\\)");
        java.util.regex.Pattern recordDeclaration =
                java.util.regex.Pattern.compile("(?s)^\\s*(public |final |static )*record\\s+\\w+\\s*\\(");

        List<Path> sources = javaSources();
        assertFalse(sources.isEmpty(), "expected Java sources under src/main/java and src/test/java");

        List<String> offending = new ArrayList<>();
        for (Path source : sources) {
            String[] lines = read(source).split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i].trim();
                if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) {
                    continue; // comments and javadoc may name newer syntax without using it
                }
                if (line.contains(textBlockStart) || streamToList.matcher(lines[i]).find()
                        || recordDeclaration.matcher(lines[i]).find()) {
                    offending.add(projectDir.relativize(source) + ":" + (i + 1) + ": " + line);
                }
            }
        }
        assertTrue(offending.isEmpty(),
                "sources must compile with maven.compiler.release 11; move JSON text blocks to src/test/resources and "
                        + "use Collectors.toList() instead of Stream.toList(): " + offending);
    }

    @Test
    void pluginDescriptorDeclaresJava11Runtime() throws IOException {
        // Users running the published plugin see plugin.xml, so the declared runtime must match the Java 11 baseline.
        Path descriptor = projectDir.resolve("target/classes/META-INF/maven/plugin.xml");
        assertTrue(Files.isRegularFile(descriptor),
                "expected the generated plugin descriptor at target/classes/META-INF/maven/plugin.xml; it is written "
                        + "by maven-plugin-plugin before the tests run");
        String content = Files.readString(descriptor, StandardCharsets.UTF_8).replace("\r\n", "\n");
        assertTrue(content.contains("<requiredJavaVersion>11</requiredJavaVersion>"),
                "the plugin descriptor must require Java 11 (the supported minimum) but declares "
                        + firstMatch(content, "<requiredJavaVersion>(.*?)</requiredJavaVersion>"));
    }

    @Test
    void docsStateTheJava11Baseline() throws IOException {
        String readme = read("README.md");
        String contributing = read("CONTRIBUTING.md");
        assertAll(
                () -> assertTrue(readme.contains("Java:** 11 or higher"),
                        "README.md must list 'Java: 11 or higher' as a prerequisite"),
                () -> assertTrue(contributing.contains("Java 11 or higher"),
                        "CONTRIBUTING.md must state that Java 11 or higher is required"),
                () -> assertFalse(readme.contains("Java:** 17 or higher"),
                        "README.md must not still advertise Java 17 as the minimum"),
                () -> assertFalse(contributing.contains("Java 17 or higher"),
                        "CONTRIBUTING.md must not still advertise Java 17 as the minimum"));
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
                        "release.yml must not reference ${{ env.VERSION }} unless it is defined at job/workflow scope"),
                () -> assertEquals(1, countOccurrences(release, "action-gh-release"),
                        "release.yml must contain exactly one action-gh-release step; a duplicated release block would "
                                + "publish the same release twice"),
                () -> assertEquals(1, countOccurrences(release, "mvn -B -ntp deploy"),
                        "release.yml must contain exactly one 'mvn -B -ntp deploy' step; a duplicated deploy block would "
                                + "fail the release once the version is already published"),
                () -> assertEquals(1, countOccurrences(release, "Create GitHub Release"),
                        "release.yml must define the 'Create GitHub Release' step exactly once")
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

    @Test
    void readmeUsageExamplesMatchThePomVersion() throws IOException {
        List<String> allowed = allowedDocumentedVersions();
        String readme = read("README.md");
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "<artifactId>sbom-aggregator-maven-plugin</artifactId>\\s*<version>([^<]+)</version>").matcher(readme);
        int found = 0;
        while (m.find()) {
            found++;
            assertTrue(allowed.contains(m.group(1).trim()),
                    "README.md plugin examples must reference one of " + allowed + " but found " + m.group(1));
        }
        assertTrue(found > 0, "README.md must contain at least one plugin usage example with a <version>");
    }

    @Test
    void issueTemplateExamplesDoNotAdvertiseAStaleVersion() throws IOException {
        List<String> allowed = allowedDocumentedVersions();
        for (String template : List.of(
                ".github/ISSUE_TEMPLATE/bug_report.md",
                ".github/ISSUE_TEMPLATE/feature_request.md")) {
            Path path = projectDir.resolve(template);
            if (!Files.isRegularFile(path)) {
                continue;
            }
            String text = read(template);
            List<String> advertised = new ArrayList<>();
            // Plugin coordinates in an XML snippet, e.g. the <version> below our artifactId.
            java.util.regex.Matcher coordinates = java.util.regex.Pattern.compile(
                    "<artifactId>sbom-aggregator-maven-plugin</artifactId>\\s*<version>([^<]+)</version>")
                    .matcher(text);
            while (coordinates.find()) {
                advertised.add(coordinates.group(1).trim());
            }
            // The free-text "Plugin Version" field of the report form.
            java.util.regex.Matcher field = java.util.regex.Pattern.compile(
                    "Plugin Version\\*\\*: \\[e\\.g\\., ([^\\]]+)]").matcher(text);
            while (field.find()) {
                advertised.add(field.group(1).trim());
            }
            // Java, Maven and OS examples in the same template are about other software, so they are not compared.
            List<String> stale = advertised.stream().filter(v -> !allowed.contains(v)).collect(Collectors.toList());
            assertTrue(stale.isEmpty(), template + " advertises stale plugin versions " + stale
                    + "; allowed plugin versions are " + allowed);
        }
    }

    /**
     * Plugin versions that user-facing examples may reference. A release build (no {@code -SNAPSHOT}) must document
     * exactly the version being released. On a development {@code X.Y.Z-SNAPSHOT} the examples may still show the
     * latest published release from CHANGELOG.md (so users are never pointed at an unpublished version right after
     * the post-release version bump) or the upcoming {@code X.Y.Z}.
     */
    private static List<String> allowedDocumentedVersions() throws IOException {
        String projectVersion = childText(pom.getDocumentElement(), "version");
        String releaseVersion = projectVersion.replace("-SNAPSHOT", "");
        List<String> allowed = new ArrayList<>();
        allowed.add(releaseVersion);
        if (projectVersion.endsWith("-SNAPSHOT")) {
            java.util.regex.Matcher released = java.util.regex.Pattern.compile(
                    "(?m)^## \\[(\\d+\\.\\d+\\.\\d+)]").matcher(read("CHANGELOG.md"));
            if (released.find()) {
                allowed.add(released.group(1));
            }
        }
        return allowed;
    }

    @Test
    void changelogHasUnreleasedSectionAndLinkForEveryRelease() throws IOException {
        String changelog = read("CHANGELOG.md");
        assertTrue(changelog.contains("\n## [Unreleased]\n"), "CHANGELOG.md must keep an [Unreleased] section");
        assertTrue(changelog.contains("\n[Unreleased]: "), "CHANGELOG.md must define the [Unreleased] link");
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)^## \\[(\\d+\\.\\d+\\.\\d+)]").matcher(changelog);
        List<String> missing = new ArrayList<>();
        int releases = 0;
        while (m.find()) {
            releases++;
            if (!changelog.contains("\n[" + m.group(1) + "]: ")) {
                missing.add(m.group(1));
            }
        }
        assertTrue(releases > 0, "CHANGELOG.md must contain at least one released version");
        assertTrue(missing.isEmpty(), "CHANGELOG.md is missing link references for " + missing);
    }

    @Test
    void mavenResolverStaysOnTheMaven39Line() {
        NodeList props = pom.getElementsByTagName("maven-resolver.version");
        assertEquals(1, props.getLength(), "pom.xml must define maven-resolver.version");
        String resolver = props.item(0).getTextContent().trim();
        assertTrue(resolver.startsWith("1.9."),
                "maven-resolver.version must match the Maven 3.9 runtime (1.9.x) but was " + resolver);
    }

    // ------------------------------------------------------------------ helpers

    private static String read(String relativePath) throws IOException {
        Path path = projectDir.resolve(relativePath);
        assertTrue(Files.isRegularFile(path), relativePath + " is missing from the project");
        return read(path);
    }

    private static String read(Path path) throws IOException {
        return Files.readString(path, StandardCharsets.UTF_8).replace("\r\n", "\n");
    }

    /** All Java sources of the project, main and test. */
    private static List<Path> javaSources() throws IOException {
        List<Path> sources = new ArrayList<>();
        for (String root : List.of("src/main/java", "src/test/java")) {
            Path dir = projectDir.resolve(root);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                files.filter(file -> file.toString().endsWith(".java")).forEach(sources::add);
            }
        }
        return sources;
    }

    /** First capture of {@code regex} in {@code text}, or the text itself when it does not match. */
    private static String firstMatch(String text, String regex) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.DOTALL)
                .matcher(text);
        return matcher.find() ? matcher.group(1).trim() : "nothing";
    }

    /** Counts non-overlapping occurrences of {@code needle} in {@code haystack}. */
    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int index = haystack.indexOf(needle);
        while (index >= 0) {
            count++;
            index = haystack.indexOf(needle, index + needle.length());
        }
        return count;
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
    void documentedVersionAllowListIsNarrow() throws IOException {
        // Guards the helper itself: it must fail closed. It may only accept the version being released and, on a
        // -SNAPSHOT build, the newest release in CHANGELOG.md -- never an older release and never a -SNAPSHOT string.
        String projectVersion = childText(pom.getDocumentElement(), "version");
        List<String> allowed = allowedDocumentedVersions();
        assertTrue(allowed.contains(projectVersion.replace("-SNAPSHOT", "")),
                "allowed versions " + allowed + " must contain the version being released");
        for (String version : allowed) {
            assertEquals(version.replace("-SNAPSHOT", ""), version,
                    "documented versions must never be snapshots: " + allowed);
        }
        assertTrue(!allowed.contains("1.0.0"),
                "an older release must not be accepted as documentation target: " + allowed);
        if (!projectVersion.endsWith("-SNAPSHOT")) {
            assertEquals(1, allowed.size(), "a release build must document exactly " + projectVersion);
        }
    }

    @Test
    void dependencyScopesAreSane() {
        // Guards the helper itself: a dependency without an explicit scope is compile scoped in Maven terms.
        assertEquals("test", dependencyScopes().get("org.junit.jupiter:junit-jupiter"));
        assertEquals("provided", dependencyScopes().get("org.apache.maven:maven-core"));
    }
}
