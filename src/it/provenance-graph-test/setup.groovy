import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import groovy.json.JsonOutput

File basedirFile = basedir as File
File repoDir = new File(basedirFile, "it-repo")
repoDir.mkdirs()

println "Creating local file repo at: ${repoDir.absolutePath}"

File artifactDir(File repoDir, String groupId, String artifactId, String version) {
    return new File(repoDir, "${groupId.replace('.', '/')}/${artifactId}/${version}")
}

// Writes pom + empty jar for groupId:artifactId:version with the given compile dependencies ("g:a:v" strings)
void writeArtifact(File repoDir, String groupId, String artifactId, String version, List<String> deps = []) {
    File dir = artifactDir(repoDir, groupId, artifactId, version)
    dir.mkdirs()
    def depsXml = deps.collect { gav ->
        def (g, a, v) = gav.split(':')
        "    <dependency><groupId>${g}</groupId><artifactId>${a}</artifactId><version>${v}</version></dependency>"
    }.join('\n')
    new File(dir, "${artifactId}-${version}.pom").text = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${groupId}</groupId>
  <artifactId>${artifactId}</artifactId>
  <version>${version}</version>
  <packaging>jar</packaging>
  <dependencies>
${depsXml}
  </dependencies>
</project>
"""
    ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(new File(dir, "${artifactId}-${version}.jar")))
    zos.putNextEntry(new ZipEntry('META-INF/'))
    zos.closeEntry()
    zos.close()
}

String purlOf(String gav) {
    def (g, a, v) = gav.split(':')
    return "pkg:maven/${g}/${a}@${v}"
}

Map componentOf(String gav) {
    def (g, a, v) = gav.split(':')
    return [type: 'library', 'bom-ref': purlOf(gav), group: g, name: a, version: v, purl: purlOf(gav)]
}

// Writes the attached CycloneDX SBOM of `gav`: its metadata.component is the artifact itself, `components` lists the
// artifact plus `listed` and `dependencies` holds the given edges (gav -> [gav...]), all by purl bom-ref
void writeSbom(File repoDir, String gav, List<String> listed, Map<String, List<String>> edges) {
    def (g, a, v) = gav.split(':')
    def bom = [
        bomFormat   : 'CycloneDX',
        specVersion : '1.5',
        version     : 1,
        metadata    : [component: componentOf(gav)],
        components  : ([gav] + listed).collect { componentOf(it) },
        dependencies: edges.collect { from, to -> [ref: purlOf(from), dependsOn: to.collect { purlOf(it) }] }
    ]
    new File(artifactDir(repoDir, g, a, v), "${a}-${v}-cyclonedx.json").text = JsonOutput.toJson(bom)
}

// root -> lib-a -> lib-b -> lib-c, root -> lib-d -> lib-b (diamond on lib-b); lib-c ships no SBOM
writeArtifact(repoDir, 'it.prov', 'lib-a', '1.0.0', ['it.prov:lib-b:1.0.0'])
writeArtifact(repoDir, 'it.prov', 'lib-d', '1.0.0', ['it.prov:lib-b:1.0.0'])
writeArtifact(repoDir, 'it.prov', 'lib-b', '1.0.0', ['it.prov:lib-c:1.0.0'])
writeArtifact(repoDir, 'it.prov', 'lib-c', '1.0.0')
writeSbom(repoDir, 'it.prov:lib-a:1.0.0', ['it.prov:lib-b:1.0.0'], ['it.prov:lib-a:1.0.0': ['it.prov:lib-b:1.0.0']])
writeSbom(repoDir, 'it.prov:lib-d:1.0.0', ['it.prov:lib-b:1.0.0'], ['it.prov:lib-d:1.0.0': ['it.prov:lib-b:1.0.0']])
// lib-b's SBOM does not mention lib-c: the lib-c placeholder must still be hung under lib-b, not under the root
writeSbom(repoDir, 'it.prov:lib-b:1.0.0', [], ['it.prov:lib-b:1.0.0': []])

println "Local repo content created"
return true
