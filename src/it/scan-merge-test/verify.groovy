import groovy.json.JsonSlurper

File aggregatedBom = new File(basedir, "target/aggregated-bom.json")
assert aggregatedBom.exists() : "Aggregated SBOM file was not created"

def bom = new JsonSlurper().parse(aggregatedBom)
assert bom.bomFormat == "CycloneDX"
assert bom.specVersion == "1.5"

String rootRef = bom.metadata.component."bom-ref"
def children = { String ref -> (bom.dependencies.find { it.ref == ref }?.dependsOn ?: []) as Set }
def inferred = { c -> (c.properties ?: []).any { it.name == "sbomAggregator:inferredDependency" && it.value == "true" } }
def reachable = { String start ->
    Set seen = [] as Set
    List todo = [start]
    while (!todo.isEmpty()) {
        String ref = todo.remove(0)
        if (seen.add(ref)) {
            todo.addAll(children(ref))
        }
    }
    seen
}

// the scanned jar and the Maven dependency are one component (matched by canonical purl)
def jars = bom.components.findAll { it.name == "jackson-databind" }
assert jars.size() == 1 : "jackson-databind must be merged into a single component, got ${jars.size()}"
def jar = jars[0]
def core = bom.components.find { it.name == "jackson-core" }
def image = bom.components.find { it.type == "container" }
def rpm = bom.components.find { it.purl?.startsWith("pkg:rpm/redhat/bash@") }
def shaded = bom.components.find { it.name == "shaded-helper" }
assert core && image && rpm && shaded

// Maven parent -> jar edge, jar's dependsOn from the Maven SBOM only
assert children(rootRef).contains(jar."bom-ref") : "Maven parent -> jar edge missing"
assert children(jar."bom-ref") == [core."bom-ref"] as Set : "jar dependsOn must come from the Maven SBOM only: ${children(jar."bom-ref")}"
assert !inferred(jar)

// scan levels: image -> jar kept; the dropped jar -> shaded edge is re-anchored under the image
assert children(image."bom-ref").contains(jar."bom-ref") : "image -> jar edge missing"
assert children(image."bom-ref").contains(shaded."bom-ref") : "shaded helper must hang under the image"
assert inferred(shaded) : "re-anchored component must carry the inferred marker"

// rpm: not linked by the scan, so it is anchored under the image and reachable from the root
assert children(image."bom-ref").contains(rpm."bom-ref")
assert inferred(rpm)
assert rpm.purl.contains("arch=x86_64")
Set fromRoot = reachable(rootRef)
[jar, core, image, rpm, shaded].each { assert fromRoot.contains(it."bom-ref") : "${it.name} not reachable from root" }

// compositions: the scan's top component has an unknown aggregate
def unknown = bom.compositions.findAll { it.aggregate == "unknown" }.collectMany { (it.assemblies ?: []) + (it.dependencies ?: []) } as Set
assert unknown.contains(image."bom-ref") : "image must be listed as aggregate unknown: ${bom.compositions}"

println("SUCCESS: scan-merge-test verified - scan merged into Maven hierarchy")
