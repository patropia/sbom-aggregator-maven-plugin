package nl.patropia.maven.plugin;

import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Dependency;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AggregateSbomMojoCollectTest {

    @Test
    void directVsTransitive() throws Exception {
        MavenProject project = new MavenProject();
        // dependencies list (direct)
        Dependency d1 = new Dependency();
        d1.setGroupId("com.example");
        d1.setArtifactId("direct-lib");
        d1.setVersion("1.0.0");
        d1.setScope("compile");

        project.setDependencies(Collections.singletonList(d1));

        // artifacts (transitive) - include an extra transitive artifact
        DefaultArtifact a1 = artifact("com.example", "direct-lib", "1.0.0", "compile");
        DefaultArtifact a2 = artifact("com.example", "transitive-lib", "2.0.0", "runtime");
        project.setArtifacts(new java.util.HashSet<>(Arrays.asList(a1, a2)));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);

        // when includeTransitive=false, should only see direct dependency
        mojo.setIncludeTransitive(false);
        List<AggregateSbomMojo.DepCoord> coords = mojo.collectDependencyCoords();
        assertEquals(1, coords.size());
        assertEquals("direct-lib", coords.get(0).artifactId);

        // when includeTransitive=true, should see both artifacts
        mojo.setIncludeTransitive(true);
        coords = mojo.collectDependencyCoords();
        // order is not guaranteed between set iteration, so check contains
        assertTrue(coords.stream().anyMatch(c -> "direct-lib".equals(c.artifactId)));
        assertTrue(coords.stream().anyMatch(c -> "transitive-lib".equals(c.artifactId)));
    }

    @Test
    void defaultScopesAndExplicitTestScope() throws Exception {
        MavenProject project = new MavenProject();
        Dependency dCompile = new Dependency();
        dCompile.setGroupId("g"); dCompile.setArtifactId("a"); dCompile.setVersion("1"); dCompile.setScope(null);
        Dependency dTest = new Dependency();
        dTest.setGroupId("g"); dTest.setArtifactId("b"); dTest.setVersion("1"); dTest.setScope("test");
        project.setDependencies(Arrays.asList(dCompile, dTest));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);

        // default scopes (null/empty -> compile & runtime) so test should be excluded
        mojo.setIncludeTransitive(false);
        mojo.setIncludeScopes(null);
        List<AggregateSbomMojo.DepCoord> coords = mojo.collectDependencyCoords();
        assertEquals(1, coords.size());
        assertEquals("a", coords.get(0).artifactId);

        // explicit test scope
        mojo.setIncludeScopes(Collections.singletonList("test"));
        coords = mojo.collectDependencyCoords();
        assertEquals(1, coords.size());
        assertEquals("b", coords.get(0).artifactId);
    }

    @Test
    void nullScopeCountsAsCompile() throws Exception {
        MavenProject project = new MavenProject();
        Dependency d = new Dependency();
        d.setGroupId("g"); d.setArtifactId("a"); d.setVersion("1"); d.setScope(null);
        project.setDependencies(Collections.singletonList(d));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(false);
        mojo.setIncludeScopes(null);

        List<AggregateSbomMojo.DepCoord> coords = mojo.collectDependencyCoords();
        assertEquals(1, coords.size());
        assertEquals("compile", coords.get(0).scope);
    }

    @Test
    void excludesPatternsAndDotHandling() throws Exception {
        MavenProject project = new MavenProject();
        Dependency d1 = new Dependency(); d1.setGroupId("com.acme"); d1.setArtifactId("foo"); d1.setVersion("1");
        Dependency d2 = new Dependency(); d2.setGroupId("comXacme"); d2.setArtifactId("foo"); d2.setVersion("1");
        Dependency d3 = new Dependency(); d3.setGroupId("org.other"); d3.setArtifactId("bar"); d3.setVersion("1");
        Dependency d4 = new Dependency(); d4.setGroupId("g"); d4.setArtifactId("a"); d4.setVersion("1");
        project.setDependencies(Arrays.asList(d1,d2,d3,d4));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(false);
        mojo.setIncludeScopes(null);
        mojo.setExcludes(Arrays.asList("com.acme:*", "*:bar", "g:a"));

        List<AggregateSbomMojo.DepCoord> coords = mojo.collectDependencyCoords();
        // d1 excluded by com.acme:* ; d3 excluded by *:bar ; d4 excluded by exact g:a ; d2 should remain
        assertEquals(1, coords.size());
        assertEquals("comXacme", coords.get(0).groupId);
        assertEquals("foo", coords.get(0).artifactId);
    }

    @Test
    void dedupeKeepsFirstSeenOrder() throws Exception {
        MavenProject project = new MavenProject();
        Dependency d1 = new Dependency(); d1.setGroupId("g"); d1.setArtifactId("a"); d1.setVersion("1");
        Dependency d2 = new Dependency(); d2.setGroupId("g"); d2.setArtifactId("a"); d2.setVersion("1");
        Dependency d3 = new Dependency(); d3.setGroupId("g"); d3.setArtifactId("b"); d3.setVersion("1");
        project.setDependencies(Arrays.asList(d1,d2,d3));

        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(false);
        mojo.setIncludeScopes(null);

        List<AggregateSbomMojo.DepCoord> coords = mojo.collectDependencyCoords();
        assertEquals(2, coords.size());
        assertEquals("a", coords.get(0).artifactId);
        assertEquals("b", coords.get(1).artifactId);
    }

    @Test
    void warnsWhenIncludeTransitiveWithUnsupportedScopes() throws Exception {
        MavenProject project = new MavenProject();
        project.setDependencies(Collections.emptyList());
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(true);
        mojo.setIncludeScopes(Arrays.asList("test","provided"));

        RecordingLog log = new RecordingLog();
        mojo.setLog(log);

        // Call validateConfiguration to trigger the warning (ensure required fields are set)
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setOutputName("aggregated-bom");
        mojo.validateConfiguration();

        assertTrue(log.warnMessages.stream().anyMatch(m -> m.contains("includeTransitive") && m.contains("COMPILE_PLUS_RUNTIME")), "Expected warning about resolution scope");
    }

    @Test
    void doesNotWarnForDefaultScopesWithTransitive() throws Exception {
        MavenProject project = new MavenProject();
        project.setDependencies(Collections.emptyList());
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(true);
        mojo.setIncludeScopes(null);

        RecordingLog log = new RecordingLog();
        mojo.setLog(log);

        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setOutputName("aggregated-bom");
        mojo.validateConfiguration();

        assertTrue(log.warnMessages.isEmpty(),
                "Default scopes must not warn about resolution scope, got: " + log.warnMessages);
    }

    @Test
    void doesNotWarnWhenTransitiveIsDisabledEvenWithTestScope() throws Exception {
        MavenProject project = new MavenProject();
        project.setDependencies(Collections.emptyList());
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        setField(mojo, "project", project);
        mojo.setIncludeTransitive(false);
        mojo.setIncludeScopes(Arrays.asList("test", "provided"));

        RecordingLog log = new RecordingLog();
        mojo.setLog(log);

        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setOutputName("aggregated-bom");
        mojo.validateConfiguration();

        assertTrue(log.warnMessages.isEmpty(),
                "includeTransitive=false must not trigger the resolution-scope warning, got: " + log.warnMessages);
    }

    // ---------------- helpers ----------------

    private static DefaultArtifact artifact(String groupId, String artifactId, String version, String scope) {
        return new DefaultArtifact(groupId, artifactId, version, scope, "jar", null, new DefaultArtifactHandler("jar"));
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = AggregateSbomMojo.class.getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    // Simple recording logger used to assert on warnings
    static class RecordingLog extends org.apache.maven.plugin.logging.SystemStreamLog {
        List<String> warnMessages = new ArrayList<>();
        @Override
        public void warn(CharSequence content) {
            warnMessages.add(String.valueOf(content));
            super.warn(content);
        }
        @Override
        public void warn(CharSequence content, Throwable error) {
            warnMessages.add(String.valueOf(content));
            super.warn(content, error);
        }
    }
}
