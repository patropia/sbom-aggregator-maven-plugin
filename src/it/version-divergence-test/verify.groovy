import groovy.json.JsonSlurper

File aggregatedBom = new File(basedir, "target/aggregated-bom.json")
assert aggregatedBom.exists() : "Aggregated SBOM file was not created"
def bom = new JsonSlurper().parse(aggregatedBom)
String logText = new File(basedir, "build.log").text

String rootRef = bom.metadata.component['bom-ref']
assert rootRef : "metadata.component must carry a bom-ref"
List components = bom.components ?: []
Map<String, List<String>> edges = [:]
(bom.dependencies ?: []).each { edges[it.ref] = (it.dependsOn ?: []) as List }

Map propsOf(def component) { (component?.properties ?: []).collectEntries { [(it.name): it.value] } }
def byPurl = { String purl -> components.findAll { it.purl == purl } }

// Graph invariants (shared with the other provenance ITs): bom-refs are unique, every ref/dependsOn target exists,
// and every component is reachable from metadata.component
def checkGraphInvariants = {
    List<String> refs = components.collect { it['bom-ref'] }
    assert !refs.contains(null) : "every component must carry a bom-ref"
    assert refs.size() == refs.toSet().size() : "duplicate bom-refs: ${refs.countBy { it }.findAll { it.value > 1 }.keySet()}"
    Set<String> known = (refs + [rootRef]) as Set
    (bom.dependencies ?: []).each { dep ->
        assert known.contains(dep.ref) : "dependencies ref '${dep.ref}' has no component"
        (dep.dependsOn ?: []).each { assert known.contains(it) : "dependsOn target '${it}' of '${dep.ref}' has no component" }
    }
    Set<String> seen = [rootRef] as Set
    List<String> queue = [rootRef]
    while (queue) {
        (edges[queue.remove(0)] ?: []).each { if (seen.add(it)) { queue << it } }
    }
    Set<String> unreachable = known - seen
    assert !unreachable : "components not reachable from ${rootRef}: ${unreachable}"
}

String libAPurl = "pkg:maven/it.div/lib-a@1.0.0"
String libX1Purl = "pkg:maven/it.div/lib-x@1.0.0"

// (a) lib-x 1.0.0, as listed by lib-a's SBOM, is flagged with the version Maven actually resolved
List libX1 = byPurl(libX1Purl)
assert libX1.size() == 1 : "expected exactly one lib-x@1.0.0 component, found ${libX1.size()}"
def libX1Component = libX1[0]
Map libX1Props = propsOf(libX1Component)
assert libX1Props["sbomAggregator:mavenResolvedVersion"] == "2.0.0" : "lib-x@1.0.0 must record Maven's resolved version 2.0.0, props: ${libX1Props}"
assert libX1Props["sbomAggregator:versionDivergence"] == "true" : "lib-x@1.0.0 must be marked versionDivergence=true, props: ${libX1Props}"

// (b) the sub-SBOM's own record is untouched: version, bom-ref and lib-a's edge to it
assert libX1Component.version == "1.0.0" : "lib-x version must not be rewritten, was ${libX1Component.version}"
assert libX1Component['bom-ref'] == libX1Purl : "lib-x bom-ref must not be rewritten, was ${libX1Component['bom-ref']}"
List libA = byPurl(libAPurl)
assert libA.size() == 1 : "expected exactly one lib-a component, found ${libA.size()}"
String libARef = libA[0]['bom-ref']
assert edges[libARef]?.contains(libX1Purl) : "lib-a must still depend on lib-x@1.0.0, dependsOn: ${edges[libARef]}"
assert edges[rootRef]?.contains(libARef) : "root must depend on lib-a, dependsOn: ${edges[rootRef]}"

// (c) components whose versions agree with Maven are not flagged
Map libAProps = propsOf(libA[0])
assert !libAProps.containsKey("sbomAggregator:mavenResolvedVersion") : "lib-a must not be flagged, props: ${libAProps}"
assert !libAProps.containsKey("sbomAggregator:versionDivergence") : "lib-a must not be flagged, props: ${libAProps}"
components.findAll { it.purl == "pkg:maven/it.div/lib-x@2.0.0" }.each {
    assert !propsOf(it).containsKey("sbomAggregator:versionDivergence") : "lib-x@2.0.0 is the resolved version and must not be flagged"
}

// (d) exactly one divergence warning, naming the mediated library
List divergenceLines = logText.readLines().findAll { it.contains("Version divergence:") }
assert divergenceLines.size() == 1 : "expected exactly one 'Version divergence:' log line, found ${divergenceLines.size()}: ${divergenceLines}"
assert divergenceLines[0].contains("it.div:lib-x: 1.0.0 -> 2.0.0") : "divergence warning must name it.div:lib-x: 1.0.0 -> 2.0.0, was: ${divergenceLines[0]}"

// (e) graph invariants
checkGraphInvariants()

println("SUCCESS: version divergence flagged without rewriting the sub-SBOM's version, bom-ref or edges")
return true
