import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import groovy.json.JsonOutput

File basedirFile = basedir as File
File repoDir = new File(basedirFile, "it-repo")
repoDir.mkdirs()

println "Creating local file repo at: ${repoDir.absolutePath}"

// Helper to write a minimal pom
void writePom(File dir, String groupId, String artifactId, String version, List<Map> deps = []) {
    dir.mkdirs()
    File pom = new File(dir, "${artifactId}-${version}.pom")
    def depsXml = deps.collect { d ->
        """
        <dependency>
            <groupId>${d.groupId}</groupId>
            <artifactId>${d.artifactId}</artifactId>
            <version>${d.version}</version>
            ${d.scope ? "<scope>${d.scope}</scope>" : ""}
        </dependency>
        """
    }.join('\n')

    pom.text = """
<project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>${groupId}</groupId>\n  <artifactId>${artifactId}</artifactId>\n  <version>${version}</version>\n  <packaging>jar</packaging>\n  <dependencies>\n${depsXml}\n  </dependencies>\n</project>
""".stripIndent()
}

// Helper to write an empty jar
void writeJar(File dir, String artifactId, String version) {
    dir.mkdirs()
    File jar = new File(dir, "${artifactId}-${version}.jar")
    ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jar))
    zos.putNextEntry(new ZipEntry('META-INF/'))
    zos.closeEntry()
    zos.close()
}

// Helper to write a small cyclonedx SBOM with one marker component
void writeSbom(File dir, String artifactId, String markerName) {
    dir.mkdirs()
    def bom = [
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: [component: [type: 'library', name: markerName, version: '1.0.0'] ],
        components: [[type: 'library', name: markerName, version: '1.0.0', purl: "pkg:maven/it.marker/${markerName}@1.0.0"]]
    ]
    File sbom = new File(dir, "${artifactId}-1.0.0-cyclonedx.json")
    sbom.text = JsonOutput.toJson(bom)
}

// lib-a depends on lib-b (compile), it.transitive.excluded:lib-x (compile), and lib-c (runtime)
writePom(new File(repoDir, "it/transitive/lib-a/1.0.0"), 'it.transitive', 'lib-a', '1.0.0', [
    [groupId: 'it.transitive', artifactId: 'lib-b', version: '1.0.0'],
    [groupId: 'it.transitive.excluded', artifactId: 'lib-x', version: '1.0.0'],
    [groupId: 'it.transitive', artifactId: 'lib-c', version: '1.0.0', scope: 'runtime']
])
writeJar(new File(repoDir, "it/transitive/lib-a/1.0.0"), 'lib-a', '1.0.0')
writeSbom(new File(repoDir, "it/transitive/lib-a/1.0.0"), 'lib-a', 'marker-from-lib-a')

// lib-b has no deps
writePom(new File(repoDir, "it/transitive/lib-b/1.0.0"), 'it.transitive', 'lib-b', '1.0.0')
writeJar(new File(repoDir, "it/transitive/lib-b/1.0.0"), 'lib-b', '1.0.0')
writeSbom(new File(repoDir, "it/transitive/lib-b/1.0.0"), 'lib-b', 'marker-from-lib-b')

// lib-x (excluded) has no deps
writePom(new File(repoDir, "it/transitive/excluded/lib-x/1.0.0"), 'it.transitive.excluded', 'lib-x', '1.0.0')
writeJar(new File(repoDir, "it/transitive/excluded/lib-x/1.0.0"), 'lib-x', '1.0.0')
writeSbom(new File(repoDir, "it/transitive/excluded/lib-x/1.0.0"), 'lib-x', 'marker-from-lib-x')

// lib-c has no SBOM (to simulate missing SBOM)
writePom(new File(repoDir, "it/transitive/lib-c/1.0.0"), 'it.transitive', 'lib-c', '1.0.0')
writeJar(new File(repoDir, "it/transitive/lib-c/1.0.0"), 'lib-c', '1.0.0')

// lib-t (test-scoped) has an SBOM but test scope should be ignored
writePom(new File(repoDir, "it/transitive/lib-t/1.0.0"), 'it.transitive', 'lib-t', '1.0.0')
writeJar(new File(repoDir, "it/transitive/lib-t/1.0.0"), 'lib-t', '1.0.0')
writeSbom(new File(repoDir, "it/transitive/lib-t/1.0.0"), 'lib-t', 'marker-from-lib-t')

println "Local repo content created"
return true
