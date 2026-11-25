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
String a = refOf('it.anonroot:lib-a:1.0.0')
String b = refOf('it.anonroot:lib-b:1.0.0')
String d = refOf('it.anonroot:lib-d:1.0.0')

// R13: the hand-written project SBOM (metadata.component with a local bom-ref and name only, no purl/GAV) is
// recognised as the project itself, so its root dependencies become the root's dependsOn
assert rootRef == "pkg:maven/nl.patropia.maven.it/project-sbom-anonymous-root@1.0.0-SNAPSHOT" : "unexpected root ${rootRef}"
assert !components.any { it.name == 'project-sbom-anonymous-root' } : "the project must not appear as a separate component"
assert !components.any { it['bom-ref'] == 'app' } : "the local bom-ref 'app' must be an alias of the root"
assert (edges[rootRef] as Set) == ([a, d] as Set) : "root must depend on exactly lib-a and lib-d, dependsOn: ${edges[rootRef]}"
assert edges[a]?.contains(b) : "lib-a must depend on lib-b, dependsOn: ${edges[a]}"
assert !edges[rootRef]?.contains(b) : "lib-b is transitive and must not be flattened onto the root"
// isolation guard: this IT uses its own groupId; any extra component (e.g. a missing-SBOM placeholder) means
// artifacts leaked in from another IT through the shared local repository
assert (components.collect { it['bom-ref'] } as Set) == ([a, b, d] as Set) : "expected only lib-a, lib-b, lib-d, found ${components.collect { it['bom-ref'] }}"
assert !components.any { c -> c.properties?.any { it.name?.endsWith('missingSbom') } } : "no missing-SBOM placeholder expected"

// metadata of the project SBOM is merged into the root
assert bom.metadata.component.description == "Hand-written project SBOM without purl or GAV" : "root description must be copied"
assert bom.metadata.licenses?.any { it.license?.id == 'Apache-2.0' } : "metadata.licenses must be copied"

checkGraphInvariants()

println("SUCCESS: anonymous project SBOM recognised as the root")
return true
