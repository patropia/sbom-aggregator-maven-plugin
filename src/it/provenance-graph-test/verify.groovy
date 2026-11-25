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

def refOf = { String gav ->
    List found = byPurl("pkg:maven/" + gav.replaceFirst(':', '/').replaceFirst(':', '@'))
    assert found.size() == 1 : "expected exactly one component for ${gav}, found ${found.size()}"
    return found[0]['bom-ref']
}
String a = refOf('it.prov:lib-a:1.0.0')
String b = refOf('it.prov:lib-b:1.0.0')
String c = refOf('it.prov:lib-c:1.0.0')
String d = refOf('it.prov:lib-d:1.0.0')

// Multi-hop path root -> lib-a -> lib-b -> lib-c through dependsOn edges
assert edges[rootRef]?.contains(a) : "root must depend on lib-a, dependsOn: ${edges[rootRef]}"
assert edges[a]?.contains(b) : "lib-a must depend on lib-b, dependsOn: ${edges[a]}"
assert edges[b]?.contains(c) : "lib-b must depend on the lib-c placeholder, dependsOn: ${edges[b]}"

// Diamond: lib-b keeps both incoming edges (lib-a and lib-d) and stays a single component
assert edges[rootRef]?.contains(d) : "root must depend on lib-d, dependsOn: ${edges[rootRef]}"
assert edges[d]?.contains(b) : "lib-d must depend on lib-b, dependsOn: ${edges[d]}"
Set<String> parentsOfB = edges.findAll { it.value.contains(b) }.keySet()
assert parentsOfB.containsAll([a, d]) : "lib-b must have incoming edges from lib-a and lib-d, has: ${parentsOfB}"

// lib-c is a missing-SBOM placeholder that keeps its provenance
def libC = components.find { it['bom-ref'] == c }
Map libCProps = propsOf(libC)
assert libCProps["sbomAggregator:missingSbom"] == "true" : "lib-c must be marked missingSbom=true, props: ${libCProps}"
assert libCProps["sbomAggregator:direct"] == "false" : "lib-c is transitive, props: ${libCProps}"
String trail = libCProps["sbomAggregator:dependencyTrail"]
assert trail : "lib-c must record its dependency trail"
List trailEntries = trail.split(" -> ") as List
assert trailEntries.first().startsWith("nl.patropia.maven.it:provenance-graph-test:") : "trail must start at the project, was: ${trail}"
assert trailEntries.last().startsWith("it.prov:lib-c:") : "trail must end at lib-c, was: ${trail}"
assert trailEntries.any { it.startsWith("it.prov:lib-b:") } : "trail must pass through lib-b, was: ${trail}"

// The project SBOM is the root: its direct dependencies are exactly lib-a and lib-d (nothing flattened onto it)
assert (edges[rootRef] as Set) == ([a, d] as Set) : "root must depend on exactly lib-a and lib-d, dependsOn: ${edges[rootRef]}"
assert !components.any { it.name == 'provenance-graph-test' } : "the project must not appear as a separate component"

// M2 regression guard: the transitive placeholder is not flattened onto the root
assert !edges[rootRef]?.contains(c) : "lib-c placeholder must not be a direct child of the root, root dependsOn: ${edges[rootRef]}"

checkGraphInvariants()

println("SUCCESS: multi-hop, diamond and missing-transitive provenance preserved")
return true
