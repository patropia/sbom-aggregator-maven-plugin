import groovy.json.JsonSlurper

// Two aggregations run in the same build with the same fixed outputTimestamp. The aggregated SBOM must
// be reproducible: same serialNumber, same metadata.timestamp and the same component order.
File targetDir = new File(basedir, "target")
File first = new File(targetDir, "reproducible-a.json")
File second = new File(targetDir, "reproducible-b.json")

assert first.exists() : "First aggregated SBOM was not created (${first})"
assert second.exists() : "Second aggregated SBOM was not created (${second})"

def slurper = new JsonSlurper()
def a = slurper.parse(first)
def b = slurper.parse(second)

assert a.serialNumber != null : "The aggregated SBOM must carry a serialNumber"
assert a.serialNumber == b.serialNumber :
    "serialNumber must be reproducible with a fixed outputTimestamp but was ${a.serialNumber} and ${b.serialNumber}"

assert a.metadata != null && a.metadata.timestamp != null : "metadata.timestamp must be set"
assert a.metadata.timestamp == b.metadata.timestamp :
    "metadata.timestamp must be reproducible but was ${a.metadata.timestamp} and ${b.metadata.timestamp}"

assert a.metadata.timestamp.toString().startsWith("2024-01-01T00:00:00") :
    "metadata.timestamp must be derived from the configured outputTimestamp but was ${a.metadata.timestamp}"

def refs = { bom -> bom.components.collect { it.'bom-ref' ?: it.name } }
assert refs(a) == refs(b) : "Component order must be stable between runs: ${refs(a)} vs ${refs(b)}"
assert refs(a).size() == 2 : "Expected the two components from the base SBOM but got ${refs(a)}"

// The aggregated output must itself be schema valid (validateOutput defaults to true, so the build
// would have failed already; this checks the document is still parseable and complete).
assert a.bomFormat == "CycloneDX"
assert a.specVersion == "1.5"

println("SUCCESS: aggregated SBOM is reproducible (serial ${a.serialNumber}, timestamp ${a.metadata.timestamp})")
