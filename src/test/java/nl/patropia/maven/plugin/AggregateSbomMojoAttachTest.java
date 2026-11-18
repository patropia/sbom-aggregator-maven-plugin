package nl.patropia.maven.plugin;

import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link AggregateSbomMojo#execute()} with a stub {@link MavenProjectHelper}: the
 * configuration guards, the output file naming and the attach behaviour (including attach failures).
 */
class AggregateSbomMojoAttachTest {

    @Test
    void attachesAggregatedSbomWithClassifierAndExtension(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);

        mojo.execute();

        assertEquals(1, helper.calls.size(), "the aggregated SBOM must be attached once");
        assertEquals("json", helper.calls.get(0).type);
        assertEquals("cyclonedx", helper.calls.get(0).classifier);
        assertEquals("aggregated-bom.json", helper.files.get(0).getName());
        assertTrue(helper.files.get(0).exists(), "the attached file must exist on disk");
        assertEquals(helper.project, projectOf(mojo), "the project must be passed to the helper");
    }

    @Test
    void doesNotAttachWhenAttachIsDisabled(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setAttach(false);

        mojo.execute();

        assertTrue(helper.calls.isEmpty(), "nothing must be attached when attach=false");
        assertTrue(Files.exists(tempDir.resolve("aggregated-bom.json")),
                "the SBOM file is still written when attaching is disabled");
    }

    @Test
    void rejectsBlankOutputClassifierWhenAttaching(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setOutputClassifier("   ");

        MojoExecutionException error = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(error.getMessage().contains("outputClassifier"),
                "message should name the setting: " + error.getMessage());
        assertTrue(helper.calls.isEmpty());
        assertFalse(Files.exists(tempDir.resolve("aggregated-bom.json")),
                "an invalid configuration must fail before anything is written");
    }

    @Test
    void rejectsNullOutputClassifierWhenAttaching(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = newMojo(tempDir, new RecordingProjectHelper());
        mojo.setOutputClassifier(null);

        assertThrows(MojoExecutionException.class, mojo::execute);
    }

    @Test
    void allowsBlankOutputClassifierWhenNotAttaching(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setAttach(false);
        mojo.setOutputClassifier("  ");

        mojo.execute();

        assertTrue(helper.calls.isEmpty());
        assertTrue(Files.exists(tempDir.resolve("aggregated-bom.json")));
    }

    @Test
    void trimsOutputClassifier(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setOutputClassifier("  cyclonedx-aggregated  ");

        mojo.execute();

        assertEquals("cyclonedx-aggregated", helper.calls.get(0).classifier);
    }

    @Test
    void attachFailureFailsTheBuild(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        helper.failOnAttach = true;
        AggregateSbomMojo mojo = newMojo(tempDir, helper);

        MojoExecutionException error = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(error.getMessage().contains("attach"),
                "the message should explain that attaching failed: " + error.getMessage());
        assertTrue(error.getCause() instanceof IllegalStateException,
                "the original failure must be preserved as the cause");
    }

    @Test
    void warnsButStillAttachesWhenAClassifierClashExists(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        MavenProject project = projectOf(mojo);
        project.addAttachedArtifact(
                new DefaultArtifact(
                        "com.acme",
                        "root",
                        VersionRange.createFromVersion("1.0.0"),
                        "compile",
                        "json",
                        "cyclonedx",
                        new DefaultArtifactHandler("json")
                ));

        mojo.execute();

        assertEquals(1, helper.calls.size(), "a clash only produces a warning, it must not stop the attach");
        assertEquals("cyclonedx", helper.calls.get(0).classifier);
    }

    @Test
    void usesOutputNameForTheWrittenFile(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setOutputName("my-sbom");

        mojo.execute();

        assertTrue(Files.exists(tempDir.resolve("my-sbom.json")));
        assertEquals("my-sbom.json", helper.files.get(0).getName());
    }

    @Test
    void normalisesOutputExtensionAndFileName(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setOutputExtension(" XML ");

        mojo.execute();

        assertTrue(Files.exists(tempDir.resolve("aggregated-bom.xml")),
                "the extension must be lower-cased in the file name");
        assertEquals("xml", helper.calls.get(0).type);
    }

    @Test
    void rejectsOutputNameThatEscapesTheOutputDirectory(@TempDir Path tempDir) throws Exception {
        for (String invalid : new String[] {"../evil", "sub/dir/bom", "sub\\dir\\bom", "  ", "..", "a..b"}) {
            AggregateSbomMojo mojo = newMojo(tempDir, new RecordingProjectHelper());
            mojo.setOutputName(invalid);
            assertThrows(MojoExecutionException.class, mojo::execute,
                    "outputName '" + invalid + "' must be rejected");
        }
    }

    @Test
    void rejectsUnsupportedSpecVersionAndExtension(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo badSpec = newMojo(tempDir, new RecordingProjectHelper());
        badSpec.setSpecVersion("1.2");
        assertThrows(MojoExecutionException.class, badSpec::execute);

        AggregateSbomMojo badExtension = newMojo(tempDir, new RecordingProjectHelper());
        badExtension.setOutputExtension("yaml");
        assertThrows(MojoExecutionException.class, badExtension::execute);

        AggregateSbomMojo nullExtension = newMojo(tempDir, new RecordingProjectHelper());
        nullExtension.setOutputExtension(null);
        assertThrows(MojoExecutionException.class, nullExtension::execute);
    }

    @Test
    void skipsExecutionWithoutWritingOrAttaching(@TempDir Path tempDir) throws Exception {
        RecordingProjectHelper helper = new RecordingProjectHelper();
        AggregateSbomMojo mojo = newMojo(tempDir, helper);
        mojo.setSkip(true);
        mojo.setOutputName("../not-even-validated");

        mojo.execute();

        assertTrue(helper.calls.isEmpty(), "skip must short-circuit the attach step");
        try (var files = Files.list(tempDir)) {
            assertTrue(files.findAny().isEmpty(), "skip must not write any file");
        }
    }

    @Test
    void failsWhenProjectHelperIsMissing(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = newMojo(tempDir, null);

        MojoExecutionException error = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(error.getMessage().toLowerCase().contains("projecthelper")
                        || error.getMessage().toLowerCase().contains("project helper"),
                "the message should explain that the project helper is missing: " + error.getMessage());
    }

    @Test
    void validateConfigurationTrimsAndLowerCasesSettings(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = newMojo(tempDir, new RecordingProjectHelper());
        mojo.setSpecVersion(" 1.6 ");
        mojo.setOutputExtension(" JSON ");
        mojo.setOutputName("  my-bom  ");
        mojo.setOutputClassifier("  my-classifier  ");

        mojo.validateConfiguration();

        assertEquals("1.6", field(mojo, "specVersion"));
        assertEquals("json", field(mojo, "outputExtension"));
        assertEquals("my-bom", field(mojo, "outputName"));
        assertEquals("my-classifier", field(mojo, "outputClassifier"));
    }

    @Test
    void validateConfigurationRejectsBlankOutputName(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = newMojo(tempDir, new RecordingProjectHelper());
        mojo.setOutputName(null);
        assertThrows(MojoExecutionException.class, mojo::validateConfiguration);

        mojo.setOutputName("   ");
        assertThrows(MojoExecutionException.class, mojo::validateConfiguration);
    }

    @Test
    void validateConfigurationAcceptsDefaultClassifier(@TempDir Path tempDir) throws Exception {
        AggregateSbomMojo mojo = newMojo(tempDir, new RecordingProjectHelper());
        mojo.validateConfiguration();
        assertEquals("cyclonedx", field(mojo, "outputClassifier"));
    }

    // --------------------------------------------------------------- helpers

    private static Object field(Object target, String name) throws Exception {
        Field field = AggregateSbomMojo.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = AggregateSbomMojo.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static MavenProject projectOf(AggregateSbomMojo mojo) throws Exception {
        return (MavenProject) field(mojo, "project");
    }

    private static AggregateSbomMojo newMojo(Path dir, MavenProjectHelper helper) throws Exception {
        AggregateSbomMojo mojo = new AggregateSbomMojo();
        mojo.setSpecVersion("1.5");
        mojo.setOutputExtension("json");
        mojo.setOutputName("aggregated-bom");
        mojo.setOutputClassifier("cyclonedx");
        mojo.setOutputDirectory(dir.toFile());
        mojo.setProjectSbom(dir.resolve("missing-base-bom.json").toFile());
        mojo.setAttach(true);
        mojo.setProjectHelper(helper);

        MavenProject project = new MavenProject();
        project.setGroupId("com.acme");
        project.setArtifactId("root");
        project.setVersion("1.0.0");
        set(mojo, "project", project);
        return mojo;
    }

    private static final class RecordingProjectHelper implements MavenProjectHelper {

        private final List<Call> calls = new ArrayList<>();
        private final List<File> files = new ArrayList<>();
        private MavenProject project;
        private boolean failOnAttach;

        @Override
        public void attachArtifact(MavenProject project, String artifactType, String artifactClassifier, File artifactFile) {
            record(project, artifactType, artifactClassifier, artifactFile);
        }

        @Override
        public void attachArtifact(MavenProject project, String artifactType, File artifactFile) {
            record(project, artifactType, null, artifactFile);
        }

        @Override
        public void attachArtifact(MavenProject project, File artifactFile, String artifactClassifier) {
            record(project, null, artifactClassifier, artifactFile);
        }

        @Override
        public void addResource(MavenProject p, String dir, List<String> includes, List<String> excludes) {
            // no-op for tests
        }

        @Override
        public void addTestResource(MavenProject p, String dir, List<String> includes, List<String> excludes) {
            // no-op for tests
        }

        private void record(MavenProject project, String artifactType, String artifactClassifier, File artifactFile) {
            if (failOnAttach) {
                throw new IllegalStateException("cannot attach " + artifactFile);
            }
            this.project = project;
            calls.add(new Call(artifactType, artifactClassifier));
            files.add(artifactFile);
        }
    }

    private static final class Call {
        private final String type;
        private final String classifier;

        private Call(String type, String classifier) {
            this.type = type;
            this.classifier = classifier;
        }
    }
}
